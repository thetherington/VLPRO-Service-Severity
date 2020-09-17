import requests
import json
from threading import Thread


class severity_mon:
    def find_activeVLPRO(self):

        for ip in self.vlpros:

            try:

                url = "http://%s:%s%s" % (ip, self.port, self.ping)

                resp = requests.get(url, timeout=2)
                resp.close()

            except Exception:
                continue

            if resp.text == "pong":

                self.vlpros.insert(0, self.vlpros.pop(self.vlpros.index(ip)))

                return ip

        return None

    def get_services(self, vlpro_ip):

        if vlpro_ip:

            try:

                url = "http://%s:%s%s" % (vlpro_ip, self.port, self.get_element_url)

                resp = requests.get(url, timeout=2)
                resp.close()

                query_result = json.loads(resp.text)

                for list_item in query_result["ungrouped"]:

                    if isinstance(list_item, dict):
                        if self.group in list_item.keys():

                            return [list_item[self.group], vlpro_ip]

            except Exception:

                return [None, vlpro_ip]

        return [None, vlpro_ip]

    def fetch_service_hardware(self, vlpro_ip, service):

        if vlpro_ip and service:

            try:

                url = "http://%s:%s%s" % (vlpro_ip, self.port, self.get_service_hardware)
                url = url.replace("__placeholder__", service)

                resp = requests.get(url, timeout=2)
                resp.close()

                query_result = json.loads(resp.text)

                return query_result[0]

            except Exception:
                pass

        return None

    def fetch_suppression_state(self, vlpro_ip, service):

        if vlpro_ip and service:

            try:

                url = "http://%s:%s%s" % (vlpro_ip, self.port, self.get_suppression_state)
                url = url.replace("__placeholder__", service)

                resp = requests.get(url, timeout=2)
                resp.close()

                query_result = json.loads(resp.text)

                return query_result["result"]

            except Exception:
                pass

        return None

    def fetch_element_alarms(self, vlpro_ip, service):

        if vlpro_ip and service:

            try:

                url = "http://%s:%s%s" % (vlpro_ip, self.port, self.get_element_alarms)
                url = url.replace("__placeholder__", service)

                resp = requests.get(url, timeout=2)
                resp.close()

                query_result = json.loads(resp.text)

                un_cor, un_ack = 0, 0

                for alarms in query_result["results"]:

                    if not alarms["acked"]:
                        un_ack += 1

                    if not alarms["corrected"]:
                        un_cor += 1

                return {"un_cor": un_cor, "un_ack": un_ack}

            except Exception:
                pass

        return None

    def get_severity(self):

        self.collection = []
        threadsService = []

        Services, vlpro_ip = self.get_services(self.find_activeVLPRO())

        if Services and vlpro_ip:

            try:

                url = "http://%s:%s%s" % (vlpro_ip, self.port, self.get_service_severity)

                resp = requests.get(url, timeout=2)
                resp.close()

                query_result = json.loads(resp.text)

                for service in query_result:

                    if any(match in service["name"] for match in Services):

                        threadsService.append(
                            Thread(target=self.process_severity, args=(vlpro_ip, service))
                        )

                for x in threadsService:
                    x.start()

                for y in threadsService:
                    y.join()

            except Exception:
                pass

        return self.collection

    def process_severity(self, vlpro_ip, service):

        try:

            service["type"] = "service"
            service["active_vlpro"] = vlpro_ip

            service.update(self.severity_format_key[int(service["severity"])])

            service["device_ip"] = self.fetch_service_hardware(vlpro_ip, service["name"])
            service["suppression"] = self.fetch_suppression_state(vlpro_ip, service["name"])

            service.update(self.fetch_element_alarms(vlpro_ip, service["name"]))

            type_parts = self.hardware_collection.get(service["device_ip"])
            service["device_type"] = (
                type_parts.get("productType") if isinstance(type_parts, dict) else None
            )

            self.collection.append(service)

            return service

        except Exception:
            pass

        return None

    def collect_hardware(self, vlpro_ip):

        hardware_collection = None

        if vlpro_ip:

            try:

                url = "http://%s:%s%s" % (vlpro_ip, self.port, self.get_hardware)

                resp = requests.get(url, timeout=2)
                resp.close()

                query_result = json.loads(resp.text)

                hardware_collection = {}

                for hardware in query_result:

                    hardware_collection[hardware["address"]] = {}
                    hardware_collection[hardware["address"]] = hardware

            except Exception:
                pass

        return hardware_collection

    def fetch_severity_format(self, vlpro_ip):

        severity_keys = None

        if vlpro_ip:

            try:

                url = "http://%s:%s%s" % (vlpro_ip, self.port, self.get_severity_format)

                resp = requests.get(url, timeout=2)
                resp.close()

                query_result = json.loads(resp.text)

                severity_keys = {}

                for severity in query_result:

                    severity["severity"] = int(severity["severity"])
                    severity_keys[severity["severity"]] = {}

                    severity["desc"] = (
                        severity["desc"].replace(" Blink", "").replace("None", "Running")
                    )
                    severity["color"] = severity["color"].replace("#94918c", "#00ff00")

                    severity_keys[severity["severity"]] = severity

            except Exception:
                pass

        return severity_keys

    def create_summary(self, doc_collection):

        issues = [int(doc["fields"]["severity"]) for doc in doc_collection]

        if issues:

            fields = {
                "number_issues": sum([1 if issue > 0 else 0 for issue in issues]),
                "number_services": len(issues),
                "flashing": "true"
                if "true" in (doc["fields"]["flashing"] for doc in doc_collection)
                else "false",
                "highest_issue_desc": self.severity_format_key[max(issues)]["desc"],
                "highest_issue_color": self.severity_format_key[max(issues)]["color"],
                "un_ack": sum([doc["fields"]["un_ack"] for doc in doc_collection]),
                "un_cor": sum([doc["fields"]["un_cor"] for doc in doc_collection]),
                "insite_ip": self.insite_ip,
                "type": "summary",
            }

            return fields

        return None

    def __init__(self, **kwargs):

        self.port = "8082"
        self.group = "insite"
        self.get_element_url = "/vistalink/1/elements/service.json?groups=true"
        self.get_service_severity = "/vistalink/1/service/severity.json?isVerbose=false"
        self.ping = "/vistalink/1/ping.json?"
        self.get_service_hardware = (
            "/vistalink/1/service/__placeholder__/hardware.json?magnumIDs=false"
        )
        self.get_hardware = (
            "/vistalink/1/hardware.json?labels=false&magnumIDs=false&productType=true"
        )
        self.get_severity_format = "/vistalink/1/severity/format.json?"
        self.get_suppression_state = (
            "/vistalink/1/alarm/element/__placeholder__/suppression.json?elementType=service"
        )
        self.get_element_alarms = "/vistalink/1/alarm/element/__placeholder__/details.json?maxCount=1000&isVerbose=true&elementType=service"
        self.vlpros = []
        self.insite_ip = None
        self.collection = []

        for key, value in kwargs.items():

            if "group" in key:
                self.group = value

            if "vlpros" in key:
                self.vlpros.extend(value)

            if "self.port" in key:
                self.port = value

            if "insite_ip" in key:
                self.insite_ip = value

        if self.vlpros:

            self.hardware_collection = self.collect_hardware(self.find_activeVLPRO())
            self.severity_format_key = self.fetch_severity_format(self.find_activeVLPRO())


def main():

    services = severity_mon(
        group="insite", vlpros=["192.168.10.1", "192.168.10.3"], insite_ip="172.16.112.20"
    )

    documents = []

    for service in services.get_severity():

        document = {"fields": service, "host": "hosts", "name": "severity"}

        documents.append(document)

    if documents:

        document = {
            "fields": services.create_summary(documents),
            "host": "hosts",
            "name": "summary",
        }

        documents.append(document)

    return json.dumps(documents)


if __name__ == "__main__":

    print(main())
