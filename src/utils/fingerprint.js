import useragent from "useragent";

export const parsedevice = (req) => {
  const agent = useragent.parse(req.headers["user-agent"]);

  return {
    browser: agent.toAgent(),
    os: agent.os.toString(),
    device: agent.device.toString(),
    useragent: req.headers["user-agent"],
  };
};
