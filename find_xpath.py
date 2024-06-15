from lxml import etree

def find_enclosing_element(tree, line_number):
    for element in tree.iter():
        if element.sourceline <= line_number:
            # Found a candidate element, check if it's the deepest one
            deepest_element = element
        else:
            break
    return deepest_element

def get_xpath_and_line(xml_file, line_number):
    # Parse the entire XML tree
    tree = etree.parse(xml_file)
    line_content, xpath = None, None

    # Read the file line by line
    with open(xml_file, 'r') as file:
        for current_line, content in enumerate(file, start=1):
            if current_line == line_number:
                line_content = content.strip()
                # Find the enclosing element
                enclosing_element = find_enclosing_element(tree, line_number)
                if enclosing_element is not None:
                    xpath = tree.getpath(enclosing_element)
                break

    return xpath, line_content

# Example usage
xml_file = 'running_config.xml'

try:
    line_number = int(input("Enter the desired line number: "))
except ValueError:
    print("Please enter a valid integer for the line number.")
    exit(1)

xpath, line_content = get_xpath_and_line(xml_file, line_number)
print(f'XPath of line {line_number}: {xpath}')
print(f'Content of line {line_number}: {line_content}')
