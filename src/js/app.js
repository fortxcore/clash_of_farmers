import "bootstrap/js/dist/collapse";
import AOS from "aos"
// Import the functions you need from the SDKs you need
import { initializeApp } from "firebase/app";
// TODO: Add SDKs for Firebase products that you want to use
// https://firebase.google.com/docs/web/setup#available-libraries

// Your web app's Firebase configuration
const firebaseConfig = {
  apiKey: "AIzaSyAUdPcXS61wKimXLJwDHlm_QCoGXaXBYbI",
  authDomain: "geco-landing.firebaseapp.com",
  projectId: "geco-landing",
  storageBucket: "geco-landing.appspot.com",
  messagingSenderId: "29116394568",
  appId: "1:29116394568:web:cfe6b066d86e2b61673c7d"
};

// Initialize Firebase
const app = initializeApp(firebaseConfig);


document.addEventListener('DOMContentLoaded', function() {
    'use strict';
    AOS.init();

    var link = document.querySelector('.navbar-toggler');
    link.addEventListener('click', function() {
      if (link.classList.contains('toggle-menu--clicked')) {
        link.classList.remove('toggle-menu--clicked');
      } else {
        link.classList.add('toggle-menu--clicked');
      }
    }, false);
  }, false);