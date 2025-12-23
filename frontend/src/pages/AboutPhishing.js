import Navbar from "../components/Navbar";
import Footer from "../components/Footer";

function AboutPhishing() {
  return (
    <>
      <Navbar />

      <section className="page-section">
        <h1>About Phishing</h1>
        <p>
          Phishing is a cyber attack where fake websites imitate real ones to
          steal sensitive information like passwords and bank details.
        </p>
      </section>

      <Footer />
    </>
  );
}

export default AboutPhishing;
