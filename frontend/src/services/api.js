import axios from "axios";
const API = axios.create({
  baseURL: "http://127.0.0.1:5000",
  headers: { "Content-Type": "application/json" },
});
export const scanURL = (url, deep_scan = true) => {
  return API.post("/scan", { url, deep_scan });
};
