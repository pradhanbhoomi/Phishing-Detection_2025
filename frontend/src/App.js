import UrlDetect from "../src/components/UrlDetect"
import { BrowserRouter as Router, Routes, Route } from "react-router-dom";

const App = () => {
  return (
      <Routes>
        <Route path="/UrlDetect" element={<UrlDetect />} />
      </Routes>
  );
};

export default App;
