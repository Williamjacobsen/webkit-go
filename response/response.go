package response

import (
	"encoding/json"
	"net/http"
)

func WriteJSON(writer http.ResponseWriter, message any) {
	writer.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(writer).Encode(message); err != nil {
		http.Error(writer, "failed to encode response", http.StatusInternalServerError)
	}
}
