// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, Intel Corporation

#include "pcm-io-metrics.h"
#include <gtest/gtest.h>
#include <fstream>

using namespace pcm;

class FormulaEvaluatorTest : public ::testing::Test {
protected:
    FormulaEvaluator eval;
    std::unordered_map<std::string, double> noVars;
};

TEST_F(FormulaEvaluatorTest, Constants)
{
    EXPECT_DOUBLE_EQ(eval.evaluate("42", noVars), 42.0);
    EXPECT_DOUBLE_EQ(eval.evaluate("3.14", noVars), 3.14);
    EXPECT_DOUBLE_EQ(eval.evaluate("0", noVars), 0.0);
}

TEST_F(FormulaEvaluatorTest, Arithmetic)
{
    EXPECT_DOUBLE_EQ(eval.evaluate("2 + 3 * 4", noVars), 14.0);
    EXPECT_DOUBLE_EQ(eval.evaluate("(2 + 3) * 4", noVars), 20.0);
    EXPECT_DOUBLE_EQ(eval.evaluate("10 - 3 - 2", noVars), 5.0);
    EXPECT_DOUBLE_EQ(eval.evaluate("20 / 4", noVars), 5.0);
    EXPECT_DOUBLE_EQ(eval.evaluate("2 + 3", noVars), 5.0);
    EXPECT_DOUBLE_EQ(eval.evaluate("6 * 7", noVars), 42.0);
}

TEST_F(FormulaEvaluatorTest, WithVariables)
{
    std::unordered_map<std::string, double> vars = {
        {"UNC_CHA_TOR_INSERTS.IO_PCIRDCUR", 100.0},
        {"UNC_CHA_TOR_INSERTS.IO_ITOM", 50.0}
    };
    EXPECT_DOUBLE_EQ(eval.evaluate("UNC_CHA_TOR_INSERTS.IO_PCIRDCUR * 64", vars), 6400.0);
    EXPECT_DOUBLE_EQ(
        eval.evaluate("(UNC_CHA_TOR_INSERTS.IO_PCIRDCUR + UNC_CHA_TOR_INSERTS.IO_ITOM) * 64", vars),
        9600.0);
}

TEST_F(FormulaEvaluatorTest, NestedParens)
{
    std::unordered_map<std::string, double> vars = {
        {"a", 2.0}, {"b", 3.0}, {"c", 7.0}, {"d", 1.0}
    };
    // ((2+3) * (7-1)) / 2 = (5*6)/2 = 15
    EXPECT_DOUBLE_EQ(eval.evaluate("((a + b) * (c - d)) / 2", vars), 15.0);
}

TEST_F(FormulaEvaluatorTest, DivisionByZero)
{
    EXPECT_DOUBLE_EQ(eval.evaluate("10 / 0", noVars), 0.0);
    std::unordered_map<std::string, double> vars = {{"x", 0.0}};
    EXPECT_DOUBLE_EQ(eval.evaluate("42 / x", vars), 0.0);
}

TEST_F(FormulaEvaluatorTest, UnknownVariableIsZero)
{
    EXPECT_DOUBLE_EQ(eval.evaluate("UNKNOWN_EVENT * 64", noVars), 0.0);
}

TEST_F(FormulaEvaluatorTest, ExtractVariables)
{
    auto vars = eval.extractVariables("UNC_CHA_TOR_INSERTS.IO_PCIRDCUR * 64");
    EXPECT_EQ(vars.size(), 1u);
    EXPECT_EQ(vars.count("UNC_CHA_TOR_INSERTS.IO_PCIRDCUR"), 1u);

    auto vars2 = eval.extractVariables("(UNC_CHA_TOR_INSERTS.IO_ITOM + UNC_CHA_TOR_INSERTS.IO_ITOMCACHENEAR) * 64");
    EXPECT_EQ(vars2.size(), 2u);
    EXPECT_EQ(vars2.count("UNC_CHA_TOR_INSERTS.IO_ITOM"), 1u);
    EXPECT_EQ(vars2.count("UNC_CHA_TOR_INSERTS.IO_ITOMCACHENEAR"), 1u);
}

TEST_F(FormulaEvaluatorTest, ExtractVariablesNoDuplicates)
{
    auto vars = eval.extractVariables("x + x * x");
    EXPECT_EQ(vars.size(), 1u);
    EXPECT_EQ(vars.count("x"), 1u);
}

TEST_F(FormulaEvaluatorTest, ExtractVariablesNoConstants)
{
    auto vars = eval.extractVariables("42 + 3.14");
    EXPECT_TRUE(vars.empty());
}

static const char* kTestMetricsJSON = R"json({
    "metrics": [
        {
            "name": "PCIe Rd (B)",
            "formula": "UNC_CHA_TOR_INSERTS.IO_PCIRDCUR * 64",
            "short_name": "PCIeRd",
            "aggregation": "socket"
        },
        {
            "name": "PCIe Wr (B)",
            "formula": "(UNC_CHA_TOR_INSERTS.IO_ITOM + UNC_CHA_TOR_INSERTS.IO_ITOMCACHENEAR) * 64",
            "short_name": "PCIeWr",
            "aggregation": "socket"
        },
        {
            "name": "Total BW (B)",
            "formula": "(UNC_CHA_TOR_INSERTS.IO_PCIRDCUR + UNC_CHA_TOR_INSERTS.IO_ITOM + UNC_CHA_TOR_INSERTS.IO_ITOMCACHENEAR) * 64",
            "aggregation": "system"
        }
    ]
})json";

TEST(MetricsConfigTest, LoadFromString)
{
    MetricsConfig config;
    ASSERT_TRUE(config.loadFromString(kTestMetricsJSON));
    EXPECT_EQ(config.getMetrics().size(), 3u);
}

TEST(MetricsConfigTest, MetricFields)
{
    MetricsConfig config;
    ASSERT_TRUE(config.loadFromString(kTestMetricsJSON));

    const auto& metrics = config.getMetrics();
    EXPECT_EQ(metrics[0].name, "PCIe Rd (B)");
    EXPECT_EQ(metrics[0].formula, "UNC_CHA_TOR_INSERTS.IO_PCIRDCUR * 64");
    EXPECT_EQ(metrics[0].short_name, "PCIeRd");
    EXPECT_EQ(metrics[0].aggregation, "socket");

    EXPECT_EQ(metrics[1].name, "PCIe Wr (B)");
    EXPECT_EQ(metrics[1].short_name, "PCIeWr");

    EXPECT_EQ(metrics[2].name, "Total BW (B)");
    EXPECT_EQ(metrics[2].short_name, "");
    EXPECT_EQ(metrics[2].aggregation, "system");
}

TEST(MetricsConfigTest, DefaultAggregation)
{
    MetricsConfig config;
    ASSERT_TRUE(config.loadFromString(R"({
        "metrics": [
            { "name": "Foo", "formula": "x * 2" }
        ]
    })"));
    EXPECT_EQ(config.getMetrics()[0].aggregation, "socket");
}

TEST(MetricsConfigTest, ExtractEventNames)
{
    MetricsConfig config;
    ASSERT_TRUE(config.loadFromString(kTestMetricsJSON));

    auto events = config.extractEventNames();
    EXPECT_EQ(events.size(), 3u);
    EXPECT_EQ(events.count("UNC_CHA_TOR_INSERTS.IO_PCIRDCUR"), 1u);
    EXPECT_EQ(events.count("UNC_CHA_TOR_INSERTS.IO_ITOM"), 1u);
    EXPECT_EQ(events.count("UNC_CHA_TOR_INSERTS.IO_ITOMCACHENEAR"), 1u);
}

TEST(MetricsConfigTest, LoadFromStringInvalidJSON)
{
    MetricsConfig config;
    EXPECT_FALSE(config.loadFromString("not valid json"));
}

TEST(MetricsConfigTest, LoadFromStringMissingMetrics)
{
    MetricsConfig config;
    EXPECT_FALSE(config.loadFromString(R"({"other": "data"})"));
}

TEST(MetricsConfigTest, LoadFromStringEmptyMetrics)
{
    MetricsConfig config;
    EXPECT_FALSE(config.loadFromString(R"({"metrics": []})"));
}

TEST(MetricsConfigTest, LoadFromFile)
{
    const std::string path = "test_metrics_tmp.json";
    {
        std::ofstream out(path);
        out << kTestMetricsJSON;
    }
    MetricsConfig config;
    ASSERT_TRUE(config.load(path));
    EXPECT_EQ(config.getMetrics().size(), 3u);
    (void)std::remove(path.c_str());
}

TEST(MetricsConfigTest, LoadFromFileBadPath)
{
    MetricsConfig config;
    EXPECT_FALSE(config.load("nonexistent/metrics.json"));
}

// --- TableRenderer Tests ---

// Box-drawing character helpers for building expected strings
#ifdef _MSC_VER
#define B_H  "\xC4"
#define B_V  "\xB3"
#define B_TL "\xDA"
#define B_TR "\xBF"
#define B_BL "\xC0"
#define B_BR "\xD9"
#define B_TD "\xC2"
#define B_TU "\xC1"
#define B_ML "\xC3"
#define B_MR "\xB4"
#define B_X  "\xC5"
#else
#define B_H  u8"\u2500"
#define B_V  u8"\u2502"
#define B_TL u8"\u250C"
#define B_TR u8"\u2510"
#define B_BL u8"\u2514"
#define B_BR u8"\u2518"
#define B_TD u8"\u252C"
#define B_TU u8"\u2534"
#define B_ML u8"\u251C"
#define B_MR u8"\u2524"
#define B_X  u8"\u253C"
#endif

static std::string hline(int n)
{
    std::string s;
    for (int i = 0; i < n; ++i) s += B_H;
    return s;
}

class TableRendererTest : public ::testing::Test {
protected:
    TableRenderer renderer;
};

TEST_F(TableRendererTest, RenderSingleColumn)
{
    renderer.setHeaders({"Value"});
    renderer.addRow({"42"});
    std::string result = renderer.renderToString();

    // Column width = max(5, 2) + 2 = 7
    std::string expected =
        std::string(B_TL) + hline(7) + B_TR + "\n" +
        B_V + " Value " + B_V + "\n" +
        B_ML + hline(7) + B_MR + "\n" +
        B_V + "    42 " + B_V + "\n" +
        B_BL + hline(7) + B_BR + "\n";

    EXPECT_EQ(result, expected);
}

TEST_F(TableRendererTest, RenderMultipleColumns)
{
    renderer.setHeaders({"PCIeRd", "PCIeWr", "Total"});
    renderer.addRow({"1234", "5678", "6912"});
    renderer.addRow({"100", "200", "300"});
    std::string result = renderer.renderToString();

    // Col widths: max(6,4)+2=8, max(6,4)+2=8, max(5,4)+2=7
    std::string expected =
        std::string(B_TL) + hline(8) + B_TD + hline(8) + B_TD + hline(7) + B_TR + "\n" +
        B_V + " PCIeRd " + B_V + " PCIeWr " + B_V + " Total " + B_V + "\n" +
        B_ML + hline(8) + B_X + hline(8) + B_X + hline(7) + B_MR + "\n" +
        B_V + "   1234 " + B_V + "   5678 " + B_V + "  6912 " + B_V + "\n" +
        B_V + "    100 " + B_V + "    200 " + B_V + "   300 " + B_V + "\n" +
        B_BL + hline(8) + B_TU + hline(8) + B_TU + hline(7) + B_BR + "\n";

    EXPECT_EQ(result, expected);
}

TEST_F(TableRendererTest, RenderWithSectionHeader)
{
    renderer.setHeaders({"Read", "Write"});
    renderer.addSectionHeader("PCIe BW");
    renderer.addRow({"100", "200"});
    std::string result = renderer.renderToString();

    // Col widths: max(4,3)+2=6, max(5,3)+2=7
    // Table width = 6+7+3 borders = 16 display cols, inner = 14
    std::string expected =
        std::string(B_TL) + hline(6) + B_TD + hline(7) + B_TR + "\n" +
        B_V + " Read " + B_V + " Write " + B_V + "\n" +
        B_ML + hline(14) + B_MR + "\n" +
        B_V + " PCIe BW      " + B_V + "\n" +
        B_ML + hline(6) + B_TD + hline(7) + B_MR + "\n" +
        B_V + "  100 " + B_V + "   200 " + B_V + "\n" +
        B_BL + hline(6) + B_TU + hline(7) + B_BR + "\n";

    EXPECT_EQ(result, expected);
}

TEST_F(TableRendererTest, RenderEmptyTable)
{
    renderer.setHeaders({"A", "B"});
    std::string result = renderer.renderToString();

    // Col widths: 1+2=3, 1+2=3
    std::string expected =
        std::string(B_TL) + hline(3) + B_TD + hline(3) + B_TR + "\n" +
        B_V + " A " + B_V + " B " + B_V + "\n" +
        B_BL + hline(3) + B_TU + hline(3) + B_BR + "\n";

    EXPECT_EQ(result, expected);
}
