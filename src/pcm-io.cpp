// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, Intel Corporation

#include "cpucounters.h"
#include "pcm-io-metrics.h"
#include "event-resolver.h"
#include "utils.h"

#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

#define PCM_DELAY_DEFAULT 1.0

namespace pcm {

class MetricsDisplay {
public:
    void init(const MetricsConfig* config, uint32 numSockets);
    void display(std::ostream& os, bool csv, bool useLayout) const;
    void printHeader(std::ostream& os, bool csv) const;

    // Point to the platform's counter values (no copy, valid for lifetime of platform)
    void setCounterValues(const std::vector<std::unordered_map<std::string, double>>* values);

private:
    const MetricsConfig* m_config = nullptr;
    uint32 m_numSockets = 0;
    const std::vector<std::unordered_map<std::string, double>>* m_counterValues = nullptr;

    void displayLayoutMode(std::ostream& os) const;
    void displayFlatMode(std::ostream& os) const;
    void displayCsv(std::ostream& os) const;
    std::unordered_map<std::string, double> getSystemCounterValues() const;
    static std::string formatValue(double value);
    static std::string metricDisplayName(const IOMetric& metric);
};

class MetricsDrivenPlatform {
public:
    bool init(PCM* pcm, const std::string& metricsPath, const std::string& eventPrefix);
    void collect(int delayMs);
    const MetricsConfig& getConfig() const { return m_config; }
    MetricsDisplay& getDisplay() { return m_display; }
    static std::string cpuModelToDir(int cpuModel);

private:
    PCM* m_pcm = nullptr;
    uint32 m_numSockets = 0;
    MetricsConfig m_config;
    MetricsDisplay m_display;
    PerfmonEventResolver m_resolver;
    PCM::RawPMUConfigs m_pmuConfigs;

    struct EventLocation {
        std::string pmuName;
        size_t counterIndex;
    };
    std::unordered_map<std::string, EventLocation> m_eventLocations;

    std::vector<ServerUncoreCounterState> m_beforeState;
    std::vector<ServerUncoreCounterState> m_afterState;
    std::vector<std::unordered_map<std::string, double>> m_counterValues;

    void readCounterValues();
};

} // namespace pcm

using namespace std;
using namespace pcm;

// --- MetricsDrivenPlatform implementation ---

std::string MetricsDrivenPlatform::cpuModelToDir(int cpuModel)
{
    switch (cpuModel)
    {
        case (int)PCM::ICX:
            return "icelake-sp";
        default:
            return "";
    }
}

bool MetricsDrivenPlatform::init(PCM* pcm, const std::string& metricsPath, const std::string& eventPrefix)
{
    m_pcm = pcm;

    if (!m_config.load(metricsPath))
    {
        cerr << "ERROR: Failed to load metrics from " << metricsPath << "\n";
        return false;
    }

    if (!m_resolver.init(pcm->getCPUFamilyModelString(), eventPrefix))
    {
        cerr << "ERROR: Failed to initialize perfmon event resolver\n";
        cerr << "  CPU: " << pcm->getCPUFamilyModelString() << "\n";
        cerr << "  Event prefix: " << eventPrefix << "\n";
        return false;
    }

    // Resolve all events referenced in metric formulas
    auto eventNames = m_config.extractEventNames();
    for (const auto& eventName : eventNames)
    {
        if (m_eventLocations.count(eventName))
            continue;  // already resolved

        std::string pmuName;
        PCM::RawEventConfig config;
        if (!m_resolver.resolveEvent(eventName, pmuName, config))
        {
            cerr << "WARNING: Could not resolve event: " << eventName << "\n";
            continue;
        }

        size_t idx = m_pmuConfigs[pmuName].programmable.size();
        m_pmuConfigs[pmuName].programmable.push_back(config);
        m_eventLocations[eventName] = {pmuName, idx};
    }

    if (m_eventLocations.empty())
    {
        cerr << "ERROR: No events could be resolved\n";
        return false;
    }

    // Program PMUs
    PCM::ErrorCode status = pcm->program(m_pmuConfigs, true);
    if (status != PCM::Success)
    {
        pcm->checkError(status);
        return false;
    }

    // Allocate counter state vectors
    m_numSockets = pcm->getNumSockets();
    m_beforeState.resize(m_numSockets);
    m_afterState.resize(m_numSockets);
    m_counterValues.resize(m_numSockets);

    m_display.init(&m_config, m_numSockets);

    // Read initial "before" state right after programming
    m_pcm->globalFreezeUncoreCounters();
    for (uint32 s = 0; s < m_numSockets; ++s)
        m_beforeState[s] = m_pcm->getServerUncoreCounterState(s);
    m_pcm->globalUnfreezeUncoreCounters();

    return true;
}

void MetricsDrivenPlatform::collect(int delayMs)
{
    MySleepMs(delayMs);

    // Read after state
    m_pcm->globalFreezeUncoreCounters();
    for (uint32 s = 0; s < m_numSockets; ++s)
        m_afterState[s] = m_pcm->getServerUncoreCounterState(s);
    m_pcm->globalUnfreezeUncoreCounters();

    readCounterValues();
    m_display.setCounterValues(&m_counterValues);

    // After becomes before for next iteration
    std::swap(m_beforeState, m_afterState);
}

void MetricsDrivenPlatform::readCounterValues()
{
    for (uint32 s = 0; s < m_numSockets; ++s)
    {
        m_counterValues[s].clear();
        for (const auto& [eventName, loc] : m_eventLocations)
        {
            auto pmuId = m_pcm->strToUncorePMUID(loc.pmuName);
            if (pmuId == PCM::INVALID_PMU_ID) continue;

            size_t numUnits = m_pcm->getMaxNumOfUncorePMUs(pmuId, s);
            double sum = 0.0;
            for (size_t u = 0; u < numUnits; ++u)
            {
                sum += static_cast<double>(
                    getUncoreCounter(pmuId, (uint32)u, (uint32)loc.counterIndex,
                                     m_beforeState[s], m_afterState[s]));
            }
            m_counterValues[s][eventName] = sum;
        }
    }
}

// --- MetricsDisplay implementation ---

void MetricsDisplay::init(const MetricsConfig* config, uint32 numSockets)
{
    m_config = config;
    m_numSockets = numSockets;
}

void MetricsDisplay::setCounterValues(const std::vector<std::unordered_map<std::string, double>>* values)
{
    m_counterValues = values;
}

std::unordered_map<std::string, double> MetricsDisplay::getSystemCounterValues() const
{
    std::unordered_map<std::string, double> systemValues;
    for (const auto& socketValues : *m_counterValues)
    {
        for (const auto& [name, val] : socketValues)
            systemValues[name] += val;
    }
    return systemValues;
}

std::string MetricsDisplay::formatValue(double value)
{
    if (value >= 0.0 && value <= static_cast<double>(UINT64_MAX))
        return unit_format(static_cast<uint64>(value));

    std::ostringstream oss;
    oss << std::fixed << std::setprecision(2) << value;
    return oss.str();
}

std::string MetricsDisplay::metricDisplayName(const IOMetric& metric)
{
    return metric.short_name.empty() ? metric.name : metric.short_name;
}

void MetricsDisplay::printHeader(std::ostream& os, bool csv) const
{
    if (!csv) return;

    const auto& metrics = m_config->getMetrics();
    os << "Skt";
    for (const auto& metric : metrics)
    {
        if (metric.aggregation == "system") continue;
        os << "," << metricDisplayName(metric);
    }
    os << "\n";
}

void MetricsDisplay::display(std::ostream& os, bool csv, bool useLayout) const
{
    if (csv)
        displayCsv(os);
    else if (useLayout && m_config->getLayout().size() > 1)
        displayLayoutMode(os);
    else
        displayFlatMode(os);
}

void MetricsDisplay::displayCsv(std::ostream& os) const
{
    FormulaEvaluator evaluator;
    const auto& metrics = m_config->getMetrics();

    for (uint32 s = 0; s < m_numSockets; ++s)
    {
        os << s;
        for (const auto& m : metrics)
        {
            if (m.aggregation == "system") continue;
            double val = evaluator.evaluate(m.formula, (*m_counterValues)[s]);
            os << "," << static_cast<uint64>(val);
        }
        os << "\n";
    }

    auto systemValues = getSystemCounterValues();
    bool hasSystem = false;
    for (const auto& m : metrics)
    {
        if (m.aggregation == "system")
        {
            if (!hasSystem)
            {
                os << "*";
                hasSystem = true;
            }
            double val = evaluator.evaluate(m.formula, systemValues);
            os << "," << static_cast<uint64>(val);
        }
    }
    if (hasSystem) os << "\n";
}

void MetricsDisplay::displayLayoutMode(std::ostream& os) const
{
    FormulaEvaluator evaluator;
    const auto& metrics = m_config->getMetrics();

    for (const auto& section : m_config->getLayout())
    {
        std::vector<std::string> headers;
        std::vector<size_t> metricIdxs;
        bool hasSocketMetrics = false;
        bool hasSystemMetrics = false;

        for (const auto& metricName : section.metrics)
        {
            for (size_t i = 0; i < metrics.size(); ++i)
            {
                if (metrics[i].name == metricName)
                {
                    headers.push_back(metricDisplayName(metrics[i]));
                    metricIdxs.push_back(i);
                    if (metrics[i].aggregation == "system")
                        hasSystemMetrics = true;
                    else
                        hasSocketMetrics = true;
                    break;
                }
            }
        }

        if (headers.empty()) continue;

        std::vector<std::string> fullHeaders;
        if (hasSocketMetrics)
            fullHeaders.push_back("Skt");
        fullHeaders.insert(fullHeaders.end(), headers.begin(), headers.end());

        TableRenderer table;
        table.setHeaders(fullHeaders);

        if (!section.title.empty())
            table.addSectionHeader(section.title);

        if (hasSocketMetrics)
        {
            for (uint32 s = 0; s < m_numSockets; ++s)
            {
                std::vector<std::string> row;
                row.push_back(std::to_string(s));
                for (size_t idx : metricIdxs)
                {
                    if (metrics[idx].aggregation == "system") continue;
                    double val = evaluator.evaluate(metrics[idx].formula, (*m_counterValues)[s]);
                    row.push_back(formatValue(val));
                }
                table.addRow(row);
            }
        }

        if (hasSystemMetrics)
        {
            auto systemValues = getSystemCounterValues();
            std::vector<std::string> row;
            if (hasSocketMetrics) row.push_back("*");
            for (size_t idx : metricIdxs)
            {
                if (metrics[idx].aggregation != "system") continue;
                double val = evaluator.evaluate(metrics[idx].formula, systemValues);
                row.push_back(formatValue(val));
            }
            table.addRow(row);
        }

        table.render(os);
        os << "\n";
    }
}

void MetricsDisplay::displayFlatMode(std::ostream& os) const
{
    FormulaEvaluator evaluator;
    const auto& metrics = m_config->getMetrics();

    std::vector<std::string> fullHeaders = {"Skt"};
    std::vector<size_t> socketMetricIndices;
    for (size_t i = 0; i < metrics.size(); ++i)
    {
        if (metrics[i].aggregation != "system")
        {
            fullHeaders.push_back(metricDisplayName(metrics[i]));
            socketMetricIndices.push_back(i);
        }
    }

    TableRenderer table;
    table.setHeaders(fullHeaders);

    for (uint32 s = 0; s < m_numSockets; ++s)
    {
        std::vector<std::string> row;
        row.push_back(std::to_string(s));
        for (size_t idx : socketMetricIndices)
        {
            double val = evaluator.evaluate(metrics[idx].formula, (*m_counterValues)[s]);
            row.push_back(formatValue(val));
        }
        table.addRow(row);
    }

    auto systemValues = getSystemCounterValues();
    bool hasSystem = false;
    std::vector<std::string> sysRow;
    sysRow.push_back("*");
    for (size_t i = 0; i < metrics.size(); ++i)
    {
        if (metrics[i].aggregation == "system")
        {
            double val = evaluator.evaluate(metrics[i].formula, systemValues);
            sysRow.push_back(formatValue(val));
            hasSystem = true;
        }
    }
    if (hasSystem)
    {
        table.addSectionHeader("System Total");
        table.addRow(sysRow);
    }

    table.render(os);
}

// --- CLI ---

static void print_usage(const string& progname)
{
    cout << "\n Usage: \n " << progname
         << " --help | [delay] [options] [-- external_program [external_program_options]]\n";
    cout << "   <delay>                           => time interval to sample performance counters (seconds).\n";
    cout << "                                        If not specified, or 0, with external program given\n";
    cout << "                                        will read counters only after external program finishes\n";
    cout << " Supported <options> are: \n";
    cout << "  -h    | --help  | /h               => print this help and exit\n";
    cout << "  -silent                            => silence information output and print only measurements\n";
    cout << "  --version                          => print application version\n";
    cout << "  -csv[=file.csv] | /csv[=file.csv]  => output compact CSV format to screen or\n"
         << "                                        to a file, in case filename is provided\n";
    cout << "  -i[=number] | /i[=number]          => allow to determine number of iterations\n";
    cout << "  --ep <path>                        => event file prefix (perfmon directory path)\n";
    cout << "  --metrics <path>                   => custom metrics.json file path\n";
    cout << "  --no-layout                        => flat output without section grouping\n";
    cout << "  --validate                         => validate events against perfmon and exit\n";
    cout << "\n";
    cout << " Examples:\n";
    cout << "  " << progname << " 1                  => print counters every second\n";
    cout << "  " << progname << " 0.5 -csv=test.log  => save counter values to test.log in CSV format\n";
    cout << "  " << progname << " --validate          => check which metrics are available on this CPU\n";
    cout << "\n";
}

static double resolveDelay(double delay, bool csv, bool hasExternalCmd, PCM* m)
{
    m->setBlocked(hasExternalCmd && delay <= 0.0);

    if (csv)
    {
        if (delay <= 0.0) delay = PCM_DELAY_DEFAULT;
    }
    else
    {
        if (((delay < 1.0) && (delay > 0.0)) || (delay <= 0.0))
        {
            cerr << "For non-CSV mode delay < 1.0s does not make a lot of practical sense. "
                    "Default delay 1s is used. Consider CSV mode for lower delay values\n";
            delay = PCM_DELAY_DEFAULT;
        }
    }

    cerr << "Update every " << delay << " seconds\n";

    return delay;
}

static bool printValidation(std::ostream& os, const std::string& metricsPath,
                            const std::string& cpuFamilyModel, const std::string& eventPrefix)
{
    MetricsConfig config;
    if (!config.load(metricsPath))
    {
        cerr << "ERROR: Failed to load metrics from " << metricsPath << "\n";
        return false;
    }
    PerfmonEventResolver resolver;
    if (!resolver.init(cpuFamilyModel, eventPrefix))
    {
        cerr << "ERROR: Failed to initialize event resolver\n";
        return false;
    }
    config.printValidatedMetrics(os, [&resolver](const std::string& event) { return resolver.isEvent(event); });
    return true;
}

static std::string findMetricsPath(const std::string& programPath, const std::string& platformDir)
{
    if (platformDir.empty()) return "";

    const std::string relPath = "pmu-events/" + platformDir + "/metrics.json";

    // 1. Next to the binary (post-build copy)
    size_t lastSlash = programPath.find_last_of('/');
    std::string binDir = (lastSlash != std::string::npos) ? programPath.substr(0, lastSlash) : ".";
    std::string candidate = binDir + "/" + relPath;
    if (std::ifstream(candidate).good()) return candidate;

    // 2. Install path
    candidate = getInstallPathPrefix() + relPath;
    if (std::ifstream(candidate).good()) return candidate;

    return "";
}

PCM_MAIN_NOTHROW;

int mainThrows(int argc, char* argv[])
{
    if (print_version(argc, argv))
        exit(EXIT_SUCCESS);

    null_stream nullStream2;
#ifdef PCM_FORCE_SILENT
    null_stream nullStream1;
    cout.rdbuf(&nullStream1);
    cerr.rdbuf(&nullStream2);
#else
    check_and_set_silent(argc, argv, nullStream2);
#endif

    set_signal_handlers();

    cerr << "\n";
    cerr << " Intel(r) Performance Counter Monitor: Metrics-Driven I/O Bandwidth Monitoring Utility\n";
    cerr << " This utility measures I/O bandwidth using JSON-defined metrics and perfmon events\n";
    cerr << "\n";

    double delay = -1.0;
    bool csv = false;
    bool useLayout = true;
    bool validateOnly = false;
    std::string eventPrefix;
    std::string metricsPath;
    char* sysCmd = nullptr;
    char** sysArgv = nullptr;
    MainLoop mainLoop;

    string program = string(argv[0]);

    PCM* m = PCM::getInstance();

    if (argc > 1) do
    {
        argv++;
        argc--;
        string arg_value;

        if (check_argument_equals(*argv, {"--help", "-h", "/h"}))
        {
            print_usage(program);
            exit(EXIT_FAILURE);
        }
        else if (check_argument_equals(*argv, {"-silent", "/silent"}))
        {
            continue;
        }
        else if (check_argument_equals(*argv, {"-csv", "/csv"}))
        {
            csv = true;
        }
        else if (extract_argument_value(*argv, {"-csv", "/csv"}, arg_value))
        {
            csv = true;
            if (!arg_value.empty())
                m->setOutput(arg_value);
            continue;
        }
        else if (mainLoop.parseArg(*argv))
        {
            continue;
        }
        else if (check_argument_equals(*argv, {"--no-layout"}))
        {
            useLayout = false;
            continue;
        }
        else if (check_argument_equals(*argv, {"--validate"}))
        {
            validateOnly = true;
            continue;
        }
        else if (check_argument_equals(*argv, {"--ep"}))
        {
            argv++;
            argc--;
            if (argc <= 0)
            {
                cerr << "ERROR: no parameter provided for option --ep\n";
                exit(EXIT_FAILURE);
            }
            eventPrefix = *argv;
            continue;
        }
        else if (check_argument_equals(*argv, {"--metrics"}))
        {
            argv++;
            argc--;
            if (argc <= 0)
            {
                cerr << "ERROR: no parameter provided for option --metrics\n";
                exit(EXIT_FAILURE);
            }
            metricsPath = *argv;
            continue;
        }
        else if (check_argument_equals(*argv, {"--"}))
        {
            argv++;
            sysCmd = *argv;
            sysArgv = argv;
            break;
        }
        else
        {
            delay = parse_delay(*argv, program, (print_usage_func)print_usage);
            continue;
        }
    } while (argc > 1);

    // Auto-detect platform
    std::string platformDir = MetricsDrivenPlatform::cpuModelToDir(m->getCPUFamilyModel());
    if (platformDir.empty())
    {
        print_cpu_details();
        cerr << "ERROR: No metrics definition available for this CPU model.\n";
        cerr << "Use --metrics <path> to specify a custom metrics.json file.\n";
        exit(EXIT_FAILURE);
    }

    // Auto-detect paths if not specified
    // Event prefix default: "." — the resolver also checks getInstallPathPrefix()
    if (eventPrefix.empty()) eventPrefix = ".";

    if (metricsPath.empty()) metricsPath = findMetricsPath(program, platformDir);

    if (metricsPath.empty())
    {
        cerr << "ERROR: Could not find metrics.json for platform " << platformDir << "\n";
        cerr << "Use --metrics <path> to specify the file location.\n";
        exit(EXIT_FAILURE);
    }

    cerr << "Metrics file: " << metricsPath << "\n";
    cerr << "Event prefix: " << eventPrefix << "\n";

    std::string cpuFamilyModel = m->getCPUFamilyModelString();

    if (validateOnly)
    {
        cerr << "\nMetrics validation for " << platformDir << ":\n\n";
        exit(printValidation(cout, metricsPath, cpuFamilyModel, eventPrefix) ? EXIT_SUCCESS : EXIT_FAILURE);
    }

    // Initialize platform
    MetricsDrivenPlatform platform;
    if (!platform.init(m, metricsPath, eventPrefix))
    {
        cerr << "ERROR: Platform initialization failed\n\nMetrics validation:\n\n";
        printValidation(cerr, metricsPath, cpuFamilyModel, eventPrefix);
        exit(EXIT_FAILURE);
    }

    // Delay handling
    delay = resolveDelay(delay, csv, sysCmd != nullptr, m);

    const auto& config = platform.getConfig();
    cerr << "Monitoring " << config.getMetrics().size() << " metrics, " << config.extractEventNames().size() << " events\n\n";

    int delayMs = static_cast<int>(delay * 1000);

    if (sysCmd) MySystem(sysCmd, sysArgv);

    auto& display = platform.getDisplay();
    bool firstIteration = true;
    mainLoop([&]()
    {
        if (!csv) cout << flush;

        platform.collect(delayMs);

        if (firstIteration || csv)
        {
            display.printHeader(cout, csv);
            firstIteration = false;
        }

        display.display(cout, csv, useLayout);

        if (m->isBlocked()) return false;

        return true;
    });

    exit(EXIT_SUCCESS);
}
