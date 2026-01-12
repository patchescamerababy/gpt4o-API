#include "utils.h"
#include <nlohmann/json.hpp>
#include <httplib.h>

using json = nlohmann::json;

// C++ implementation of Java's ModelsHandler
// Exposes a GET /models endpoint that returns a list of available models.
void handleModels(const httplib::Request& /*req*/, httplib::Response& res) {
    try {
        json model;
        model["id"] = "gpt-4o-2024-08-06";
        model["object"] = "model";

        json resp;
        resp["object"] = "list";
        resp["data"] = json::array({ model });

        std::string body = resp.dump();
        res.set_header("Content-Type", "application/json; charset=utf-8");
        res.status = 200;
        res.body = body;
    } catch (const std::exception& e) {
        Utils::send_error(res, std::string("Models handler error: ") + e.what(), 500);
    }
}
