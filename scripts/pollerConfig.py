import json
from insite_plugin import InsitePlugin
import serviceMon


class Plugin(InsitePlugin):

  """
     Returns true if we can pass more then 1 host in through the hosts field in the fetch function
  """

  def can_group(self):
    return False

  """
       Fetches the details for the provided host
       Will return a json formatted string of the form
       @note the initial arguments may also be accessed through the use of
             the dictionary self.parameters which contains all the values
             specified in the script arguments for the poller configuration
       @param hosts, A list of hosts that we want to poll.  This will always
                     contain a single host unless can_group() returns true in
                     which all hosts we want to poll will be pushed into the
                     hosts array in a single call
       @return a single document of the structure
       {
          "fields" : {
             "fieldname": "value",
             "fieldname": value,
             ...
          },
          "host" : "host",
          "name" : "metric-group"
       }
       or
       an array of these objects [{...}, {...}, ...]
    """

  def fetch(self, hosts):

    try:

      self.services

    except Exception:

      group = self.parameters['group']
      vlpro1 = self.parameters['vlpro1']
      vlpro2 = self.parameters['vlpro2']
      insite_ip = self.parameters['insite_ip']

      self.services = serviceMon.severity_mon(group=group, vlpros=[vlpro1, vlpro2], insite_ip=insite_ip)

    documents = []

    for service in self.services.get_severity():

      document = {
          "fields": service,
          "host": hosts[-1],
          "name": "severity"
      }

      documents.append(document)

    if documents:

      document = {
          "fields": self.services.create_summary(documents),
          "host": hosts[-1],
          "name": "severity"
      }

    documents.append(document)

    return json.dumps(documents)
