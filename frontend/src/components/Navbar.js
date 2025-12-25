import { Link } from "react-router-dom";

function Navbar() {
  return (
    <nav className="navbar">
 <Link to="/" className="nav-logo">
        PhishGuard
      </Link>
      <ul className="nav-links">
        <li><Link to="/scan">Scan</Link></li>
        <li><Link to="/about-phishing">Phishing Guide</Link></li>
        <li><Link to="/about-project">About</Link></li>
      </ul>

     
    </nav>
  );
}

export default Navbar;
