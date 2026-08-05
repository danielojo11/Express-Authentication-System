import geoip from "geoip-lite";

export const getGeoData = (ip) => {
  const geo = geoip.lookup(ip);

  if (!geo) {
    return {
      country: "Unknown",
      city: "Unknown",
    };
  }

  return {
    country: geo.country,
    city: geo.city,
  };
};
