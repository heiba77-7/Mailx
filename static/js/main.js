// Nav Bar

// utilts
function getResult(data) {
  let result = {};
  let flag = true;
  authData = data.Headers["ARC-Authentication-Results"];
  if (authData) {
    if (authData.includes("spf=pass")) {
      result["SPF"] = "Pass";
    } else {
      result["SPF"] = "Fail";
      flag = false;
    }
    if (authData.includes("dkim=pass")) {
      result["DKIM"] = "Pass";
    } else {
      result["DKIM"] = "Fail";
      flag = false;
    }
    if (authData.includes("dmarc=pass")) {
      result["DMARC"] = "Pass";
    } else {
      result["DMARC"] = "Fail";
      flag = false;
    }
  } else {
    result["SPF"] = null;
    result["DKIM"] = null;
    result["DMARC"] = null;
  }
  if (data.URLs) {
    if (data.URLs.harm > 0) {
      result["URLs"] = "Fail";
      flag = false;
    } else {
      result["URLs"] = "Pass";
    }
  } else {
    result["URLs"] = "UnFound";
  }
  if (data.Attachment) {
    result["Attachment"] = data.Attachment;
    if (data.Attachment !== "Safe") {
      flag = false;
    }
  } else {
    result["Attachment"] = "UnFound";
  }
  if (
    data.Headers ||
    data.Headers["From"].includes(data.Headers["Return-Path"])
  ) {
    result["R-Path"] = "Identical";
  } else {
    result["R-Path"] = "Not-Identical";
    flag = false;
  }
  if (flag) {
    result["Final"] = "Safe";
  } else {
    result["Final"] = "Malicious";
  }
  console.log(result);
  return result;
}

function getreport(data, result) {
  logohtml = `<i class="fa-regular fa-circle-xmark"></i>`;
  document.querySelector(".innerlogo").innerHTML = logohtml;
  var resutlhtml = ``;
  for (const [key, value] of Object.entries(data)) {
    if (value && key !== "Final") {
      resutlhtml += `
    <section class="result">
    <div class="wordreslut ${
      value === "Pass" ||
      value === "Safe" ||
      value == "UnFound" ||
      value === "Identical"
        ? ""
        : "redresult"
    }">${key}</div>
    <div class="resulttext">${value}</div>
    </section>
    `;
    }
  }
  summaryhtml = ``;
  if (result.Attachment) {
    summaryhtml += `<li>The Attachment Hash Of SHA256 IS ${result.Attachment}</li>`;
  }
  if (data["R-Path"]) {
    summaryhtml += `<li>The Return path is ${data["R-Path"]} to Sender path</li>`;
  }
  if (result.Links) {
    summaryhtml += `<li>Found ${result.Links.length} URL in email</li>`;
  }
  if (result.URLs) {
    summaryhtml += `<li>After we analysed url in ${
      result.URLs.clean + result.URLs.harm
    } Security Vendor ${result.URLs.clean} Clean
    and ${result.URLs.harm} Harm
    </li>`;
  }
  totalsummaryhtml = `<section class="summaryresult">
  <section class="summarytext">
  <header ><h2>Summary : </h2></header>
  <ol>
      ${summaryhtml}
  </ol>
</section>`;
  resutlhtml += totalsummaryhtml;
  resutlhtml += `    <section class="result">
  <div class="wordreslut ${
    data["Final"] === "Safe" ? "" : "redresult"
  }">Final-R</div>
  <div class="resulttext">${data["Final"]}</div>
  </section>`;
  resutlhtml += `
      <section class="resultexit">
      <i class="fa-solid fa-arrow-right-from-bracket"></i>
      </section>`;
  document.querySelector(".content").innerHTML = resutlhtml;
  document.querySelector(".resultexit").addEventListener("click", function () {
    getHome();
  });
}

const toggleBtn = document.querySelector(".menu");
const toggleBtnIcon = toggleBtn.querySelector("i");
const dropDownMenu = document.querySelector(".dropdown-menu");

toggleBtn.onclick = function () {
  dropDownMenu.classList.toggle("open");
  const isOpen = dropDownMenu.classList.contains("open");
  toggleBtnIcon.classList.toggle("fa-bars", !isOpen);
  toggleBtnIcon.classList.toggle("fa-xmark", isOpen);
};

// Nav Bar Ends
//home js
var homehtml = `<section class="rightcontent">
<div class="right">
    <div class="header"><h1>Mailx</h1></div>
    <div class="drop-zone" id="drop-zone">
        Drag & Drop your email file here or click to upload
    </div>
    <input type="file" id="file-input" style="display:none;">
    <div class="button">
        <button onclick="analyzeEmail()">Analyze</button>
    </div>
    <div class="myresult">
        <p id="result"></p>
    </div>
</div> 
</section>
</section>
</section>`;
document.querySelector(".home").addEventListener("click", function () {
  getHome();
});
function getHome() {
  document.querySelector(".content").innerHTML = homehtml;
  window.location.href = "/";
}

document.querySelector(".dropdownhome").addEventListener("click", function () {
  getHome();
});

//member js
var memberhtml = `    <header class="header"><h1>Our Team</h1></header>
<section class="content">
    <div class="card">
        <div class="image">
            <img src="/static/images/medo.jpg" alt="">
        </div>
        <div class="name">
            <a href="https://www.linkedin.com/in/mohamed-ebrahim-5b9986235/">
            <h3>Mohamed Ebrahim</h3>
            </a>
        </div>
        <div class="job">
            <h4>Communcation Engineer FEE 55</h4>
        </div>
        <div class="breif">Grc Specialist Trainee | CTF Player | ISC2 CC</div>
        
    </div>
    <div class="card">
        <div class="image">
            <img src="/static/images/3asem.jpg" alt="">
        </div>
        <div class="name">
            <a href="https://www.linkedin.com/in/assem-elhalwany-6a0383313/">
            <h3>Asem 3ashour</h3>
            </a>
        </div>
        <div class="job">
            <h4>Communcation Engineer FEE 55</h4>
        </div>
        <div class="breif">CyberSecurity associate | CCNA | SOC</div>
    </div>
    <div class="card">
        <div class="image">
            <img src="/static/images/Doaa.JPG" alt="">
        </div>
        <div class="name">
            <a href="https://www.linkedin.com/in/doaa-ghonem-b23683282/">
            <h3>Doaa Ghonem </h3>
            </a>
        </div>
        <div class="job">
            <h4>Communcation Engineer FEE 55</h4>
        </div>
        <div class="breif">CyberSecurity associate</div>
        
    </div>
    <div class="card">
        <div class="image">
            <img src="/static/images/Doha.JPG" alt="">
        </div>
        <div class="name">
            <a href="https://www.linkedin.com/in/doha-adel-94371520b/">
            <h3>Doha Adel  </h3>
            </a>
        </div>
        <div class="job">
            <h4>Communcation Engineer FEE 55</h4>
        </div>
        <div class="breif">CyberSecurity associate</div>
        
    </div>
    
    
    <div class="card">
        <div class="image">
            <img src="/static/images/Moamen.JPG" alt="">
        </div>
        <div class="name">
            <a href="https://www.linkedin.com/in/moamen-elkhafeef-06962a244/">
            <h3>Moamen Ahmed</h3>
            </a>
        </div>
        <div class="job">
            <h4>Communcation Engineer FEE 55</h4>
        </div>
        <div class="breif">CyberSecurity associate | SOC </div>
        
    </div>
    <div class="card">
        <div class="image">
            <img src="/static/images/Walid.JPG" alt="">
        </div>
        <div class="name">
            <a href="https://www.linkedin.com/in/walid-salah-60170a213/">
            <h3>Walid salah</h3>
            </a>
        </div>
        <div class="job">
            <h4>Communcation Engineer FEE 55</h4>
        </div>
        <div class="breif">Networking | CyberSecurity associate </div>
        
    </div>
</section>

`;
document.querySelector(".members").addEventListener("click", function () {
  document.querySelector(".content").innerHTML = memberhtml;
});
document
  .querySelector(".dropdownmembers")
  .addEventListener("click", function () {
    document.querySelector(".content").innerHTML = memberhtml;
  });
//about me page

var abouthtml = `<header class="abouttoolheader">
<h1>About Mailx</h1>
</header>
</div>
<section class="toolbrief">
<header class="briefheader"><h2>About Tool :</h2></header>
<section class="briefcontent"><h5>
cybersecurity investigation tool used to detect the suspicious mails
and prevent dealing with them utiize the AI technology
in order to make the investigation process easier and faster than manual investigation
Funded by  Egyptian Academy of  Scientific Research &Technology(ASRT)
</h5></section>
</section>
<section class="mech">
<header class="mechheader">
<h2>
    The mechanism of out tool :
</h2>
</header>
<ol>
<li>
    Check Email Header ( SPF , DKIM , Message-ID , Sender , Return-path )
</li>
<li>Inspect Email content</li>
<li>Verify SMTP IP in Virustotal </li>
<li>Investgate URL At Virtotal </li>
<li>Calculate the Hash of the attachment file ( SHA1 , SHA256 , MD5 )</li>
<li>Investigate attachment's Hash at Virustotal</li>
</ol>
</section>
<sectio class="finaly">
<header class="finalyheader"><h2>Finally :</h2></header>
<section class="finalycontent"><h5>
we made an accurate decision about whether the recieved email is phishing or not 
in addition to designing an AI model by Machine Learning  to check if the recieved mail is phishing or safe 
according to collected datasets more than 20000 emails between phishing and safe emails integrated on it
</h5>
</sectio>
</section>
`;
document.querySelector(".dropdownabout").addEventListener("click", function () {
  document.querySelector(".content").innerHTML = abouthtml;
});
document.querySelector(".about").addEventListener("click", function () {
  document.querySelector(".content").innerHTML = abouthtml;
});

var contacthtml = `<div class="contact">
<header><h1>Contact Us</h1></header>
<section class="phone">
    <div class="icon"><i class="fa-solid fa-phone"></i></div>
    <div class="contactvalue"><a href="tel:+201064798913"><h4>+20 106 479 8913</h4></a></div>
</section>
<section class="email">
    <div class="icon"><i class="fa-solid fa-envelope"></i></div>
    <div class="contactvalue"><a href="mailto:me5619936@gmail.com"><h4>me5619936@gmail.com</h4></a></div>
</section>
<section class="linkedin">
    <div class="icon"><i class="fa-brands fa-linkedin"></i></div>
    <div class="contactvalue"><a href="https://www.linkedin.com/in/mohamed-ebrahim-5b9986235/"><h4>Mohamed Ebrahim</h4></a></div>
</section>
<section class="whatsapp">
    <div class="icon"><i class="fa-brands fa-whatsapp"></i></div>
    <div class="contactvalue"><a href="http://wa.me/+2001064798913"><h4>+20 106 479 8913</h4></a></div>
</section>
</div>`;

var loadinghtml = `<div class="load"></div>`;

document.querySelector(".contactpage").addEventListener("click", function () {
  document.querySelector(".content").innerHTML = contacthtml;
});
document
  .querySelector(".dropdowncontactpage")
  .addEventListener("click", function () {
    document.querySelector(".content").innerHTML = contacthtml;
  });

const dropZone = document.getElementById("drop-zone");
const fileInput = document.getElementById("file-input");

dropZone.addEventListener("click", () => fileInput.click());

fileInput.addEventListener("change", () => {
  if (fileInput.files.length) {
    updateDropZone(fileInput.files[0]);
  }
});
dropZone.addEventListener("dragover", (e) => {
  e.preventDefault();
  dropZone.classList.add("drop-zone--over");
});

dropZone.addEventListener("dragleave", () => {
  dropZone.classList.remove("drop-zone--over");
});

dropZone.addEventListener("drop", (e) => {
  e.preventDefault();
  if (e.dataTransfer.files.length) {
    fileInput.files = e.dataTransfer.files;
    updateDropZone(e.dataTransfer.files[0]);
  }
  dropZone.classList.remove("drop-zone--over");
});

function updateDropZone(file) {
  dropZone.textContent = file.name;
}

async function analyzeEmail() {
  const formData = new FormData();
  const file = fileInput.files[0];
  formData.append("file", file);

  const response = fetch("/analyze", {
    // const response = await fetch("/upload", {
    method: "POST",
    body: formData,
  });
  document.querySelector(".content").innerHTML = loadinghtml;
  response.then((res) => {
    if (res.status === 200) {
      new_res = fetch("/result", {
        method: "GET",
      });
      new_res.then((res) => {
        res.json().then((data) => {
          console.log(data);
          reportresult = getResult(data.result);
          getreport(reportresult, data.result);
        });
      });
    }
  });
}
