// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, Intel Corporation

#include "pcm-io-metrics.h"

#include <iostream>

namespace pcm {

namespace {

struct FormulaParser {
    const std::string& input;
    const std::unordered_map<std::string, double>& vars;
    size_t pos = 0;

    void skipWS()
    {
        while (pos < input.size() && input[pos] == ' ')
            ++pos;
    }

    double expression()
    {
        double left = term();
        skipWS();
        while (pos < input.size() && (input[pos] == '+' || input[pos] == '-'))
        {
            char op = input[pos++];
            double right = term();
            left = (op == '+') ? left + right : left - right;
            skipWS();
        }
        return left;
    }

    double term()
    {
        double left = factor();
        skipWS();
        while (pos < input.size() && (input[pos] == '*' || input[pos] == '/'))
        {
            char op = input[pos++];
            double right = factor();
            if (op == '*')
                left *= right;
            else
                left = (right != 0.0) ? left / right : 0.0;
            skipWS();
        }
        return left;
    }

    double factor()
    {
        skipWS();
        if (pos < input.size() && input[pos] == '(')
        {
            ++pos;
            double val = expression();
            skipWS();
            if (pos < input.size() && input[pos] == ')')
                ++pos;
            return val;
        }
        if (pos < input.size() && (std::isdigit(static_cast<unsigned char>(input[pos])) || input[pos] == '.'))
        {
            size_t start = pos;
            while (pos < input.size() && (std::isdigit(static_cast<unsigned char>(input[pos])) || input[pos] == '.'))
                ++pos;
            return std::stod(input.substr(start, pos - start));
        }
        if (pos < input.size() && (std::isalpha(static_cast<unsigned char>(input[pos])) || input[pos] == '_'))
        {
            size_t start = pos;
            while (pos < input.size() &&
                   (std::isalnum(static_cast<unsigned char>(input[pos])) || input[pos] == '_' || input[pos] == '.'))
                ++pos;
            std::string name = input.substr(start, pos - start);
            auto it = vars.find(name);
            return (it != vars.end()) ? it->second : 0.0;
        }
        return 0.0;
    }
};

} // anonymous namespace

double FormulaEvaluator::evaluate(const std::string& formula,
                                   const std::unordered_map<std::string, double>& variables) const
{
    FormulaParser parser{formula, variables};
    return parser.expression();
}

std::set<std::string> FormulaEvaluator::extractVariables(const std::string& formula) const
{
    std::set<std::string> vars;
    size_t i = 0;
    while (i < formula.size())
    {
        if (std::isalpha(static_cast<unsigned char>(formula[i])) || formula[i] == '_')
        {
            size_t start = i;
            while (i < formula.size() &&
                   (std::isalnum(static_cast<unsigned char>(formula[i])) || formula[i] == '_' || formula[i] == '.'))
                ++i;
            vars.insert(formula.substr(start, i - start));
        }
        else
        {
            ++i;
        }
    }
    return vars;
}

// --- MetricsConfig ---

#ifdef PCM_SIMDJSON_AVAILABLE

bool MetricsConfig::load(const std::string& path)
{
    try
    {
        m_jsonParser = std::make_shared<simdjson::dom::parser>();
        simdjson::dom::element doc = m_jsonParser->load(path);
        return parseMetrics(doc);
    }
    catch (std::exception& e)
    {
        std::cerr << "Error loading metrics from " << path << ": " << e.what() << "\n";
        return false;
    }
}

bool MetricsConfig::loadFromString(const std::string& jsonStr)
{
    try
    {
        m_jsonParser = std::make_shared<simdjson::dom::parser>();
        simdjson::dom::element doc = m_jsonParser->parse(jsonStr);
        return parseMetrics(doc);
    }
    catch (std::exception& e)
    {
        std::cerr << "Error parsing metrics JSON: " << e.what() << "\n";
        return false;
    }
}

bool MetricsConfig::parseMetrics(simdjson::dom::element doc)
{
    auto metricsArr = doc["metrics"];
    if (metricsArr.error())
    {
        std::cerr << "ERROR: No \"metrics\" array in metrics JSON\n";
        return false;
    }

    m_metrics.clear();
    for (simdjson::dom::object metricObj : metricsArr)
    {
        IOMetric m;
        m.name = std::string{metricObj["name"].get_c_str()};
        m.formula = std::string{metricObj["formula"].get_c_str()};

        auto shortName = metricObj["short_name"];
        if (!shortName.error())
            m.short_name = std::string{shortName.get_c_str()};

        auto agg = metricObj["aggregation"];
        if (!agg.error())
            m.aggregation = std::string{agg.get_c_str()};
        else
            m.aggregation = "socket";

        m_metrics.push_back(std::move(m));
    }
    return !m_metrics.empty();
}

#else // !PCM_SIMDJSON_AVAILABLE

bool MetricsConfig::load(const std::string&) { return false; }
bool MetricsConfig::loadFromString(const std::string&) { return false; }

#endif // PCM_SIMDJSON_AVAILABLE

std::set<std::string> MetricsConfig::extractEventNames() const
{
    std::set<std::string> allEvents;
    for (const auto& metric : m_metrics)
    {
        auto vars = m_evaluator.extractVariables(metric.formula);
        allEvents.insert(vars.begin(), vars.end());
    }
    return allEvents;
}

} // namespace pcm
