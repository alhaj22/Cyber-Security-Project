// components/Hero.js
import UrlInput from "./UrlInput";

function Hero() {
  return (
    <section className="hero">
      <h1>Detect Phishing Websites Instantly</h1>
      <p>Enter a website URL to check whether it is safe or phishing.</p>
      <UrlInput />
    </section>
  );
}

export default Hero;
