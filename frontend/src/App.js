import { Routes, Route } from "react-router-dom";

import Home from "./pages/Home";
import Scan from "./pages/Scan";
import AboutPhishing from "./pages/AboutPhishing";
import AboutProject from "./pages/AboutProject";

function App() {
  return (
    <Routes>
      <Route path="/" element={<Home />} />
      <Route path="/scan" element={<Scan />} />
      <Route path="/about-phishing" element={<AboutPhishing />} />
      <Route path="/about-project" element={<AboutProject />} />
    </Routes>
  );
}

export default App;
