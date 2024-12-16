function checkAddNode(){
    document.getElementById('act1').style.display = 'none';
    document.getElementById('act2').style.display = 'block';
}

function Action2(){
    document.getElementById('act2').style.display = 'none';
    document.getElementById('act3').style.display = 'block';
}

function Action3(){
    document.getElementById('act3').style.display = 'none';
    document.getElementById('act4').style.display = 'block';
}

function Action4(){
    var xhttp = new XMLHttpRequest();
    xhttp.onreadystatechange = function() {
        if (this.readyState == 4 && this.status == 200) {
        document.getElementById("act4").innerHTML =
        this.responseText;
        }
    };
    xhttp.open("GET", "/api/test", true);
    xhttp.send();
}


// function Action4(){
//     var xhttp = new XMLHttpRequest();
//     xhttp.onreadystatechange = function() {
//         if (this.readyState == 4 && this.status == 200) {
//             var data = JSON.parse(this.responseText);
//             var table = "<table border='1'><thead><tr><th>No</th><th>Channel</th><th>SSID</th><th>BSSID</th><th>Security</th><th>Signal</th><th>W-Mode</th><th>ExtCH</th><th>WPS</th></tr></thead><tbody>";
            
//             data.wifi.forEach(function(wifi, index) {
//                 table += "<tr>";
//                 table += "<td>" + index + "</td>";
//                 table += "<td>" + wifi.Ch + "</td>";
//                 table += "<td>" + wifi.SSID + "</td>";
//                 table += "<td>" + wifi.BSSID + "</td>";
//                 table += "<td>" + wifi.Security + "</td>";
//                 table += "<td>" + wifi.Signal + "</td>";
//                 table += "<td>" + wifi.WMode + "</td>";
//                 table += "<td>" + wifi.ExtCH + "</td>";
//                 table += "<td>" + wifi.WPS + "</td>";
//                 table += "</tr>";
//             });
            
//             table += "</tbody></table>";
//             document.getElementById("act4").innerHTML = table;
//         }
//     };
//     xhttp.open("GET", "/api/test", true);
//     xhttp.send();
// }


// Hàm gửi yêu cầu scan tới server
// function Action4() {
//     fetch('http://localhost:8443/api/test') // Thay đổi URL theo endpoint của bạn
//         .then(response => response.text())
//         .then(data => {
//             // Xử lý phản hồi từ server
//             console.log("Response from server:", data);
//             document.getElementById("act4").innerHTML = data;
//         })
//         .catch(error => console.error('Error:', error));
// }





