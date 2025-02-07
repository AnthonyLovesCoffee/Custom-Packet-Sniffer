// Initialize D3 charts
let protocolChart, connectionsChart;

// Protocol mapping function
function getProtocolName(port) {
    const protocolMap = {
        1: 'ICMP',
        6: 'TCP',
        7: 'UDP',
        17: 'UDP',
        20: 'FTP Data',
        21: 'FTP Control',
        22: 'SSH',
        23: 'Telnet',
        25: 'SMTP',
        53: 'DNS',
        67: 'DHCP',
        68: 'DHCP',
        69: 'TFTP',
        80: 'HTTP',
        110: 'POP3',
        123: 'NTP',
        143: 'IMAP',
        161: 'SNMP',
        162: 'SNMP',
        443: 'HTTPS',
        3389: 'RDP',
        8080: 'HTTP Proxy'
    };

    // convert port to number if it's a string
    const portNum = parseInt(port);
    return protocolMap[portNum] ? `${protocolMap[portNum]} (${portNum})` : `Port ${portNum}`;
}

// get network stats from the API
async function fetchNetworkStats() {
    try {
        console.log('Fetching network stats...');
        const response = await fetch('/api/stats');
        const data = await response.json();
        console.log('Received data:', data);
        updateDashboard(data);
    } catch (error) {
        console.error('Error fetching network stats:', error);
    }
}

function updateDashboard(data) {
    // update summary stats
    document.getElementById('duration').textContent = `${Math.floor(data.duration)}s`;
    document.getElementById('total-packets').textContent = data.total_packets.toLocaleString();

    // updating charts
    if (data.protocols) {
        updateProtocolChart(data.protocols);
    }
    if (data.top_connections) {
        updateConnectionsChart(data.top_connections);
    }
    
    // updating packet table if recent_packets data is available
    if (data.recent_packets) {
        updatePacketTable(data.recent_packets);
    }
}

// protocol chart
function initProtocolChart() {
    console.log('Initializing protocol chart...');
    const margin = 100; // Increased margin for labels
    const width = 600; // Increased width
    const height = 500; // Increased height
    const radius = Math.min(width - margin * 2, height - margin * 2) / 2;

    d3.select('#protocol-chart').selectAll('svg').remove();

    const svg = d3.select('#protocol-chart')
        .append('svg')
        .attr('width', width)
        .attr('height', height)
        .style('display', 'block') 
        .style('margin', 'auto')   
        .append('g')
        .attr('transform', `translate(${width / 2},${height / 2})`);

    protocolChart = {
        svg: svg,
        width: width,
        height: height,
        radius: radius
    };
}

function updateProtocolChart(protocols) {
    const {svg, radius} = protocolChart;
    
    // remove previous chart content
    svg.selectAll('*').remove();

    // convert protocols object to array and map protocol names to numbers
    const data = Object.entries(protocols)
        .map(([port, value]) => [getProtocolName(port), value])
        .sort((a, b) => b[1] - a[1]);

    const color = d3.scaleOrdinal(d3.schemeCategory10);
    const pie = d3.pie().value(d => d[1]);
    
    const arc = d3.arc()
        .innerRadius(radius * 0.5)
        .outerRadius(radius * 0.8);

    const outerArc = d3.arc()
        .innerRadius(radius * 0.9)
        .outerRadius(radius * 0.9);

    const arcs = svg.selectAll('path')
        .data(pie(data))
        .enter()
        .append('g');

    arcs.append('path')
        .attr('d', arc)
        .attr('fill', (d, i) => color(i))
        .attr('stroke', 'white')
        .style('stroke-width', '2px');

    // calculate percentages
    const total = data.reduce((sum, [_, value]) => sum + value, 0);

    arcs.append('polyline')
        .attr('points', function(d) {
            const pos = outerArc.centroid(d);
            pos[0] = radius * 0.85 * (midAngle(d) < Math.PI ? 1 : -1);
            return [arc.centroid(d), outerArc.centroid(d), pos];
        })
        .style('fill', 'none')
        .style('stroke', '#666')
        .style('stroke-width', '1px');

    // labels
    const labelHeight = 40; 
    const labelGroups = [];

    arcs.each(function(d) {
        const angle = midAngle(d);
        const pos = outerArc.centroid(d);
        
        let y = pos[1];
        
        pos[0] = radius * (angle < Math.PI ? 1 : -1);
        
        const side = angle < Math.PI ? 'right' : 'left';
        const sideLabels = labelGroups.filter(g => g.side === side);
        
        if (sideLabels.length > 0) {
            sideLabels.sort((a, b) => a.y - b.y);
            
            let placed = false;
            for (let i = 0; i < sideLabels.length; i++) {
                const current = sideLabels[i];
                const next = sideLabels[i + 1];
                
                if (!next && (current.y + labelHeight + 10) < height/2) {
                    y = current.y + labelHeight + 10;
                    placed = true;
                    break;
                } else if (next && (next.y - (current.y + labelHeight)) >= labelHeight + 10) {
                    y = current.y + labelHeight + 10;
                    placed = true;
                    break;
                }
            }
            
            if (!placed) {
                y = -height/2 + labelHeight * sideLabels.length;
            }
        }
        
        labelGroups.push({ side, y });
        
        const text = d3.select(this)
            .append('text')
            .attr('transform', `translate(${pos[0]},${y})`)
            .attr('text-anchor', angle < Math.PI ? 'start' : 'end')
            .style('font-size', '12px');
        
        const percentage = ((d.data[1] / total) * 100).toFixed(1);
        
        text.append('tspan')
            .text(d.data[0])
            .style('font-weight', 'bold');
        
        text.append('tspan')
            .text(` (${percentage}%)`)
            .style('font-size', '10px');
        
        text.append('tspan')
            .text(` ${d.data[1]} pkts`)
            .attr('x', angle < Math.PI ? 5 : -5)
            .attr('dy', '1.2em')
            .style('font-size', '10px');
            
        d3.select(this)
            .select('polyline')
            .attr('points', `
                ${arc.centroid(d)},
                ${outerArc.centroid(d)},
                ${pos[0]},${y}
            `);
    });
}

// helper function for angle calculation
function midAngle(d) {
    return d.startAngle + (d.endAngle - d.startAngle) / 2;
}

// top connections chart
function initConnectionsChart() {
    const margin = {top: 20, right: 20, bottom: 60, left: 60};
    const width = 600 - margin.left - margin.right;
    const height = 300 - margin.top - margin.bottom;

    d3.select('#connections-chart').selectAll('svg').remove();

    const svg = d3.select('#connections-chart')
        .append('svg')
        .attr('width', width + margin.left + margin.right)
        .attr('height', height + margin.top + margin.bottom)
        .append('g')
        .attr('transform', `translate(${margin.left},${margin.top})`);

    connectionsChart = {
        svg: svg,
        margin: margin,
        width: width,
        height: height
    };
}

function updateConnectionsChart(connections) {
    const {svg, width, height} = connectionsChart;
    
    svg.selectAll('*').remove();

    const data = Object.entries(connections)
        .sort((a, b) => b[1] - a[1]);

    const x = d3.scaleBand()
        .range([0, width])
        .padding(0.1);

    const y = d3.scaleLinear()
        .range([height, 0]);

    x.domain(data.map(d => d[0]));
    y.domain([0, d3.max(data, d => d[1])]);

    svg.append('g')
        .attr('transform', `translate(0,${height})`)
        .call(d3.axisBottom(x))
        .selectAll('text')
        .attr('transform', 'rotate(-45)')
        .style('text-anchor', 'end');

    svg.append('g')
        .call(d3.axisLeft(y));

    svg.selectAll('.bar')
        .data(data)
        .enter()
        .append('rect')
        .attr('class', 'bar')
        .attr('x', d => x(d[0]))
        .attr('width', x.bandwidth())
        .attr('y', d => y(d[1]))
        .attr('height', d => height - y(d[1]))
        .attr('fill', '#4f46e5');
}

function updatePacketTable(packets) {
    const tbody = document.querySelector('#packet-table tbody');
    
    tbody.innerHTML = '';
    
    packets.forEach(packet => {
        const row = document.createElement('tr');
        
        const sourceCell = document.createElement('td');
        sourceCell.textContent = packet.src_ip;
        
        const destCell = document.createElement('td');
        destCell.textContent = packet.dst_ip;
        
        const protocolCell = document.createElement('td');
        protocolCell.textContent = getProtocolName(packet.protocol);
        
        const timeCell = document.createElement('td');
        const timestamp = new Date(packet.timestamp * 1000);
        timeCell.textContent = timestamp.toLocaleTimeString();
        
        row.appendChild(sourceCell);
        row.appendChild(destCell);
        row.appendChild(protocolCell);
        row.appendChild(timeCell);
        
        tbody.appendChild(row);
    });
}

document.addEventListener('DOMContentLoaded', () => {
    console.log('Initializing dashboard...');
    initProtocolChart();
    initConnectionsChart();
    
    fetchNetworkStats();
    
    setInterval(fetchNetworkStats, 1000);
});