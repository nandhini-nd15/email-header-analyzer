import { MapContainer, TileLayer, Marker, Popup, Polyline } from "react-leaflet";
import L from "leaflet";
import "leaflet/dist/leaflet.css";

// Leaflet's default marker icons reference image paths that don't resolve
// correctly under Vite's bundler - this manually points them at the CDN
// so pins actually render instead of showing broken image icons.
delete L.Icon.Default.prototype._getIconUrl;
L.Icon.Default.mergeOptions({
  iconRetinaUrl: "https://unpkg.com/leaflet@1.9.4/dist/images/marker-icon-2x.png",
  iconUrl: "https://unpkg.com/leaflet@1.9.4/dist/images/marker-icon.png",
  shadowUrl: "https://unpkg.com/leaflet@1.9.4/dist/images/marker-shadow.png",
});

export default function HopMap({ receivedChain }) {
  const points = receivedChain
    .filter((hop) => hop.geo_lat != null && hop.geo_lon != null)
    .map((hop) => ({
      position: [hop.geo_lat, hop.geo_lon],
      hop,
    }));

  if (points.length === 0) {
    return (
      <p className="muted">
        No hops with resolvable public IP locations to plot on a map.
      </p>
    );
  }

  const center = points[Math.floor(points.length / 2)].position;
  const routeLine = points.map((p) => p.position);

  return (
    <div className="map-wrapper">
      <MapContainer
        center={center}
        zoom={3}
        scrollWheelZoom={false}
        style={{ height: "360px", width: "100%", borderRadius: "10px" }}
      >
        <TileLayer
          attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
          url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
        />
        <Polyline positions={routeLine} pathOptions={{ color: "#4f7cff", weight: 2, dashArray: "6 6" }} />
        {points.map(({ position, hop }) => (
          <Marker key={hop.hop_index} position={position}>
            <Popup>
              <strong>Hop {hop.hop_index + 1}</strong>
              <br />
              {hop.from_host || "unknown host"}
              <br />
              {hop.ip_address}
              <br />
              {[hop.geo_city, hop.geo_country].filter(Boolean).join(", ")}
            </Popup>
          </Marker>
        ))}
      </MapContainer>
    </div>
  );
}