d3.json("/libweb/data/datatest.json", function(error, data) {
    if (error) throw error;

    // Phân tích dữ liệu
    const nodes = [];
    const links = [];

    // Thêm thiết bị chính vào nodes
    nodes.push({ id: data.mac, label: data.label, node_link: data.node_link, ip : data.ip, wlan2g: data.wlan2g, wlan5g : data.wlan5g });

    // Thêm các thiết bị lân cận và client vào nodes và links
    data.DeviceInterfaces.forEach(iface => {
        iface.NeighborInfo.forEach(neighbor => {
            if (!nodes.some(node => node.id === neighbor.mac)) {
                nodes.push({ id: neighbor.mac, label: neighbor.label, node_link: neighbor.node_link, ip: neighbor.ip || 'neighbor', type: 'neighbor' });
            }
            links.push({
                source: data.mac,
                target: neighbor.mac,
                type: neighbor.node_link === 'ETHER' ? 'solid' : 'dashed'
            });
        });
    });

    data.ClientsList.forEach(client => {
        if (!nodes.some(node => node.id === client.mac)) {
            nodes.push({ id: client.mac, label: client.host_name, node_link: client.node_link, ip: client.ip || 'client', type: 'client' });
        }
        links.push({
            source: data.mac,
            target: client.mac,
            type: client.node_link === 'ETHER' ? 'solid' : 'dashed'
        });
    });

    // Khởi tạo mô phỏng D3.js
    const svg = d3.select("svg"),
        width = +svg.attr("width"),
        height = +svg.attr("height");

    const simulation = d3.forceSimulation(nodes)
        .force("link", d3.forceLink().id(d => d.id))
        .force("charge", d3.forceManyBody().strength(-1000))
        .force("center", d3.forceCenter(width / 2, height / 2));

    // Thêm các liên kết (cạnh)
    let link = svg.append("g")
        .attr("class", "links")
        .selectAll("line")
        .data(links)
        .enter().append("line")
        .attr("class", d => `link ${d.type}`)
        .attr("stroke-width", 2)
        .attr("stroke", d => d.type === 'solid' ? "darkblue" : "blue");

    // Thêm các nút (đỉnh)
    let node = svg.append("g")
        .attr("class", "nodes")
        .selectAll("g")
        .data(nodes)
        .enter().append("g")
        .call(d3.drag()
            .on("start", dragstarted)
            .on("drag", dragged)
            .on("end", dragended));

    // Thêm các vòng tròn cho các nút
    node.append("circle")
        .attr("r", d => {
            if(d.node_link === 'ETHER') return 20;
            else if (d.type === 'client') return 10;
            else return 15;
        })
        .attr("fill", d => {
            if (d.id === data.mac) return "blue";
            if (d.type === 'client') return "yellow";
            if (d.node_link === 'ETHER') return "orange";
            return "green";
        });

    // Thêm các văn bản cạnh các nút
    node.append("text")
        .attr("dy", 3)
        .attr("dx", 15)
        .text(d => d.label)
        .attr("font-size", "12px")
        .attr("fill", "#000");

    // Tạo thẻ <g> để chứa thông tin nút
    const infoGroup = svg.append('g')
        .attr('class', 'info-group')
        .style('display', 'none'); // Ẩn khi không cần thiết

    infoGroup.append('rect')
        .attr('width', 200)
        .attr('height', 100)
        .attr('fill', 'white')
        .attr('stroke', 'black');

    infoGroup.append('text')
        .attr('x', 10)
        .attr('y', 20)
        .attr('font-size', '12px')
        .attr('fill', 'black')
        .attr('class', 'info-text');

    // Hiển thị thông tin khi di chuột vào nút
    node.on('mouseover', function(event, d) {
        infoGroup.style('display', null); // Hiện thẻ thông tin
        updateInfoGroupPosition(event, d);
        if(d.id === data.mac){
            // thiết bị chính
            infoGroup.select('.info-text')
            .text(`Device Name: ${d.label}`)
            .append('tspan')
            .attr('x', 10)
            .attr('dy', '1.2em') // Di chuyển xuống dưới
            .text(`Connect: ${d.ip}`)
            .append('tspan')
            .attr('x', 10)
            .attr('dy', '1.2em') // Di chuyển xuống dưới
            .text(`Ethernet MAC: ${d.id}`)
            .append('tspan')
            .attr('x', 10)
            .attr('dy', '1.2em') // Di chuyển xuống dưới
            .text(`5Ghz MAC: ${d.wlan5g}`)
            .append('tspan')
            .attr('x', 10)
            .attr('dy', '1.2em') // Di chuyển xuống dưới
            .text(`2Ghz MAC: ${d.wlan2g}`);
        }
        else{
            // các thiết bị khác
            infoGroup.select('.info-text')
            .text(`Type connect: ${d.node_link}`)
            .append('tspan')
            .attr('x', 10)
            .attr('dy', '1.2em')
            .text(`Device Name: ${d.label}`)
            .append('tspan')
            .attr('x', 10)
            .attr('dy', '1.2em')
            .text(`MAC: ${d.id}`);
        }
        
    })
    .on('mousemove', function(event) {
        updateInfoGroupPosition(event);
    })
    .on('mouseout', function() {
        infoGroup.style('display', 'none'); // Ẩn thẻ thông tin
    });

    function updateInfoGroupPosition(event, d) {
        // Lấy tọa độ của chuột trong không gian SVG
        const [x, y] = [d3.event.clientX, d3.event.clientY];
        
        if (!isNaN(x) && !isNaN(y)) {
            // Tinh toán tọa độ tương ứng trong không gian SVG
            const svgRect = svg.node().getBoundingClientRect();
            const svgX = x - svgRect.left;
            const svgY = y - svgRect.top;

            infoGroup.attr('transform', `translate(${svgX + 20}, ${svgY - 50})`);
        } else {
            console.error('Invalid coordinates for event:', { x, y });
        }
    }

    // Cập nhật mô phỏng trên mỗi tick
    simulation
        .nodes(nodes)
        .on("tick", ticked);

    simulation.force("link")
        .links(links);

    function ticked() {
        link
            .attr("x1", d => d.source.x)
            .attr("y1", d => d.source.y)
            .attr("x2", d => d.target.x)
            .attr("y2", d => d.target.y);

        node
            .attr("transform", d => `translate(${d.x || 0},${d.y || 0})`);
    }

    function dragstarted(d) {
        if (!d3.event.active) simulation.alphaTarget(0.3).restart();
        d.fx = d.x;
        d.fy = d.y;
    }

    function dragged(d) {
        d.fx = d3.event.x;
        d.fy = d3.event.y;
        // Cập nhật tooltip khi kéo
        infoGroup.attr('transform', `translate(${d.x + 20}, ${d.y - 50})`);
    }

    function dragended(d) {
        if (!d3.event.active) simulation.alphaTarget(0);
        d.fx = null;
        d.fy = null;
    }

    // Thêm chức năng tạo và xóa nút ngẫu nhiên
    function addRandomNode() {
        const mac = `random-${Math.random().toString(36).substr(2, 12)}`;
        const node_link = Math.random() > 0.5 ? 'ETHER' : 'WiFi';
        const newNode = { id: mac, label: `Random Node`, node_link, ip: 'random', type: 'random' };
        
        nodes.push(newNode);
        links.push({
            source: data.mac,
            target: mac,
            type: node_link === 'ETHER' ? 'solid' : 'dashed'
        });

        restartSimulation();
    }

    function removeRandomNode() {
        if (nodes.length <= 1) return; // Đảm bảo luôn có ít nhất một nút

        const nodeToRemove = nodes[nodes.length - 1];
        nodes.pop();
        links = links.filter(link => link.source.id !== nodeToRemove.id && link.target.id !== nodeToRemove.id);

        restartSimulation();
    }

    function restartSimulation() {
        // Cập nhật dữ liệu cho các nút và liên kết
        link = link.data(links, d => `${d.source.id}-${d.target.id}`);
        link.exit().remove();
        link = link.enter().append("line")
            .attr("class", d => `link ${d.type}`)
            .attr("stroke-width", 2)
            .attr("stroke", d => d.type === 'solid' ? "darkblue" : "blue")
            .merge(link);

        node = node.data(nodes, d => d.id);
        node.exit().remove();
        const nodeEnter = node.enter().append("g")
            .call(d3.drag()
                .on("start", dragstarted)
                .on("drag", dragged)
                .on("end", dragended));

        nodeEnter.append("circle")
            .attr("r", d => {
                if(d.node_link === 'ETHER') return 20;
                else if (d.type === 'client') return 10;
                else return 15;
            })
            .attr("fill", d => {
                if (d.id === data.mac) return "blue";
                if (d.type === 'client') return "yellow";
                if (d.node_link === 'ETHER') return "orange";
                return "green";
            });

        nodeEnter.append("text")
            .attr("dy", 3)
            .attr("dx", 15)
            .text(d => d.label)
            .attr("font-size", "12px")
            .attr("fill", "#000");

        node = nodeEnter.merge(node);

        // Khởi động lại mô phỏng
        simulation.nodes(nodes).on("tick", ticked);
        simulation.force("link").links(links);
        simulation.alpha(1).restart();
    }

    // Thêm nút ngẫu nhiên mỗi 10 giây
    setInterval(addRandomNode, 10000);
    setInterval(removeRandomNode, 15000);
});
