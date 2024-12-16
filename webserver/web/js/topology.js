function updateGraph() {
    d3.json("./js/datatest.json", function(error, data) {
        if (error) throw error;
        // Phân tích dữ liệu
        const nodes = [];
        var links = [];

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

        svg.selectAll("*").remove(); // Xóa nội dung cũ trước khi vẽ lại

        const simulation = d3.forceSimulation(nodes)
            .force("link", d3.forceLink().id(d => d.id))
            .force("charge", d3.forceManyBody().strength(-1000))
            .force("center", d3.forceCenter(width / 2, height / 2));

        // Thêm các liên kết vào svg
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
            if(event.id === data.mac){
                infoGroup.select('.info-text')
                .text(`Device Name: ${event.label}`)
                .append('tspan')
                .attr('x', 10)
                .attr('dy', '1.2em')
                .text(`IP: ${event.ip}`)
                .append('tspan')
                .attr('x', 10)
                .attr('dy', '1.2em')
                .text(`Ethernet MAC: ${event.id}`)
                .append('tspan')
                .attr('x', 10)
                .attr('dy', '1.2em')
                .text(`5Ghz MAC: ${event.wlan5g}`)
                .append('tspan')
                .attr('x', 10)
                .attr('dy', '1.2em')
                .text(`2Ghz MAC: ${event.wlan2g}`);
            } else {
                infoGroup.select('.info-text')
                .text(`Type connect: ${event.node_link}`)
                .append('tspan')
                .attr('x', 10)
                .attr('dy', '1.2em')
                .text(`Device Name: ${event.label}`)
                .append('tspan')
                .attr('x', 10)
                .attr('dy', '1.2em')
                .text(`MAC: ${event.id}`);
            }
        })
        .on('mousemove', function(event) {
            updateInfoGroupPosition(event);
        })
        .on('mouseout', function() {
            infoGroup.style('display', 'none');
        });

        function updateInfoGroupPosition(event, d) {
            const [x, y] = [d3.event.clientX, d3.event.clientY];
            if (!isNaN(x) && !isNaN(y)) {
                const svgRect = svg.node().getBoundingClientRect();
                const svgX = x - svgRect.left;
                const svgY = y - svgRect.top;
                infoGroup.attr('transform', `translate(${svgX + 20}, ${svgY - 50})`);
            } else {
                console.error('Invalid coordinates for event:', { x, y });
            }
        }

        // Cập nhật mô phỏng trên mỗi tick
        simulation.nodes(nodes).on("tick", ticked);
        simulation.force("link").links(links);

        function ticked() {
            link.attr("x1", d => d.source.x)
                .attr("y1", d => d.source.y)
                .attr("x2", d => d.target.x)
                .attr("y2", d => d.target.y);
            node.attr("transform", d => `translate(${d.x || 0},${d.y || 0})`);
        }

        function dragstarted(d) {
            if (!d3.event.active) simulation.alphaTarget(0.3).restart();
            d.fx = d.x;
            d.fy = d.y;
        }

        function dragged(d) {
            d.fx = d3.event.x;
            d.fy = d3.event.y;
            infoGroup.attr('transform', `translate(${d.x + 20}, ${d.y - 50})`);
        }

        function dragended(d) {
            if (!d3.event.active) simulation.alphaTarget(0);
            d.fx = null;
            d.fy = null;
        }
    });
}

// Gọi hàm updateGraph ngay lập tức khi trang được tải
updateGraph();

// Định kỳ gọi hàm updateGraph mỗi 3s (3000 ms)
setInterval(updateGraph, 3000);