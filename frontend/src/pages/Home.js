// pages/Home.js
import Navbar from "../components/Navbar";
import Hero from "../components/Hero";
import AboutPhishing from "../components/AboutPhishing";
import AboutProject from "../components/AboutProject";
import Footer from "../components/Footer";

function Home() {
  return (
    <>
      <Navbar />
      <Hero />
      <AboutPhishing />
      <AboutProject />
      <Footer />
    </>
  );
}

export default Home;
