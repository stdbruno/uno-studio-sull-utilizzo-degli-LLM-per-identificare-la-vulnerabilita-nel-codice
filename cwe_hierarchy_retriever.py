import xml.etree.ElementTree as ET


class CWEWeakness:

    def __init__(self, cwe_id, name, children, parents, peers, category):
        self.cwe_id = cwe_id
        self.name = name
        self.children = children
        self.parents = parents
        self.peers = peers
        self.category = category


def get_cwes():
    base_ns = "{http://cwe.mitre.org/cwe-7}"
    cwe_tree = {}

    """
        Download the CWE XML file from https://cwe.mitre.org/data/downloads.html
        and save it in the same directory as this script.
        If you want to use an updated version of the CWE change the line below to the name of the file you downloaded.
    """
    tree = ET.parse("cwec_v4.16.xml")
    root = tree.getroot()
    for main_item in root:
        if main_item.tag == f"{base_ns}Weaknesses":
            for weakness in main_item:
                cwe_id = "CWE-" + weakness.attrib["ID"]
                cwe_name = weakness.attrib["Name"]
                cwe_children = set()
                cwe_parents = set()
                cwe_peers = set()

                if len(weakness.findall(f"{base_ns}Related_Weaknesses")) > 0:
                    for relative in weakness.findall(f"{base_ns}Related_Weaknesses")[0]:
                        if relative.attrib["Nature"] == "ChildOf":
                            cwe_parents.add("CWE-" + relative.attrib["CWE_ID"])
                        elif relative.attrib["Nature"] == "ParentOf":
                            cwe_children.add("CWE-" + relative.attrib["CWE_ID"])
                        elif relative.attrib["Nature"] == "PeerOf":
                            cwe_peers.add("CWE-" + relative.attrib["CWE_ID"])

                cwe_tree[cwe_id] = CWEWeakness(
                    cwe_id=cwe_id,
                    name=cwe_name,
                    children=cwe_children,
                    parents=cwe_parents,
                    peers=cwe_peers,
                    category=False,
                )
            cwe_tree = find_children(cwe_tree)

        elif main_item.tag == f"{base_ns}Categories":
            for category in main_item:
                cwe_id = "CWE-" + category.attrib["ID"]
                cwe_name = category.attrib["Name"]
                cwe_children = set()

                if len(category.findall(f"{base_ns}Relationships")) > 0:
                    for member in category.findall(f"{base_ns}Relationships")[0]:
                        if member.tag == f"{base_ns}Has_Member":
                            cwe_children.add("CWE-" + member.attrib["CWE_ID"])

                if cwe_id in cwe_tree.keys():
                    print(f"{cwe_id} already in the tree: it will be overwritten")
                cwe_tree[cwe_id] = CWEWeakness(
                    cwe_id=cwe_id,
                    name=cwe_name,
                    children=cwe_children,
                    parents=set(),
                    peers=set(),
                    category=True,
                )

    return cwe_tree


def find_children(cwe_tree):
    for key in cwe_tree.keys():
        cwe = cwe_tree[key]
        for parent in cwe.parents:
            other_cwe = cwe_tree[parent]
            other_cwe.children.add(cwe.cwe_id)
    return cwe_tree


if __name__ == "__main__":
    get_cwes()
