import Navbar from "../components/Navbar";
import Footer from "../components/Footer";

function AboutProject() {
  return (
    <>
      <Navbar />

      <section className="page-section">
        <h1>About This Project</h1>
        <p>
          This phishing detection system is built using React for frontend and
          Python for backend security analysis.
        </p>
      </section>

      <Footer />
    </>
  );
}

export default AboutProject;
