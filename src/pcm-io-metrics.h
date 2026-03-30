// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, Intel Corporation
#pragma once

#include <string>
#include <vector>
#include <set>
#include <unordered_map>

#ifdef PCM_SIMDJSON_AVAILABLE
#include <memory>
#include "simdjson.h"
#endif

namespace pcm {

struct IOMetric {
    std::string name;
    std::string formula;
    std::string short_name;
    std::string aggregation;  // "socket", "system", "stack"
};

class FormulaEvaluator {
public:
    double evaluate(const std::string& formula, const std::unordered_map<std::string, double>& variables) const;
    std::set<std::string> extractVariables(const std::string& formula) const;
};

class MetricsConfig {
public:
    bool load(const std::string& path);
    bool loadFromString(const std::string& jsonStr);

    const std::vector<IOMetric>& getMetrics() const { return m_metrics; }
    std::set<std::string> extractEventNames() const;

private:
    std::vector<IOMetric> m_metrics;
    FormulaEvaluator m_evaluator;

#ifdef PCM_SIMDJSON_AVAILABLE
    bool parseMetrics(simdjson::dom::element doc);
    std::shared_ptr<simdjson::dom::parser> m_jsonParser;
#endif
};

} // namespace pcm
