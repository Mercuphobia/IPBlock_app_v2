let nodes = [];

function addSelectedNodes(){
    let checkboxes = document.querySelectorAll('.mac-checkbox:checked');
    checkboxes.forEach(checkbox => {
        let row = checkbox.closest('tr');
        let macAddress = row.querySelector('td:last-child').textContent;

        // xoa node khoi danh sach
        nodes = nodes.filter(node => node.id !== macAddress);
        // xoa hang
        row.remove();

        // thong bao
        alert('node add successfully');

    });
}

fetch('./js/datatest.json')
    .then(response => {
        if (!response.ok) {
            throw new Error('false');
        }
        return response.json();
    })
    .then(data => {
        //console.log(data);

        data.DeviceInterfaces.forEach(iface => {
            iface.NeighborInfo.forEach(neighbor => {
                if (!nodes.some(node => node.id === neighbor.mac)) {
                    nodes.push({ 
                        id: neighbor.mac, 
                        label: neighbor.label, 
                        node_link: neighbor.node_link, 
                        ip: neighbor.ip || 'neighbor', 
                        type: 'neighbor' 
                    });
                }
            });
        });

        // them cac hang vao bang
        let tableBody = document.getElementById('macTable');
        nodes.forEach(node => {
            let row = document.createElement('tr');

            // tao cot dia chi mac
            let macCell = document.createElement('td');
            macCell.textContent = node.id;
            row.appendChild(macCell);

            // tao cot checkbox
            let checkboxCell = document.createElement('td');
            let checkbox = document.createElement('input');
            checkbox.type = 'checkbox';
            checkbox.classList.add('mac-checkbox');
            checkboxCell.appendChild(checkbox);
            row.appendChild(checkboxCell);

            tableBody.appendChild(row);
        });
        document.getElementById('selectAll').addEventListener('change',function(){
            let checkboxes = document.querySelectorAll('.mac-checkbox')
            checkboxes.forEach(check => {
                check.checked = this.checked;
            });
        });

        
        //nodes.forEach(listNode => console.log(listNode.id))

        // nhan add node


    })
    .catch(error => {
        console.error('Lỗi:', error);
    });

