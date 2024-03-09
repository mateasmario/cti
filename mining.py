import requests
from datetime import datetime
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

LIMIT = 400
MAX_OFFSET = 48000
ENDPOINT_URL = "https://bugzilla.mozilla.org/rest/bug?resolution=FIXED&bug_status=RESOLVED&bug_status=VERIFIED&bug_status=CLOSED&classification=Client%20Software&classification=Developer%20Infrastructure&classification=Components&classification=Server%20Software&classification=Other&query_format=advanced&product=Firefox&limit="
SECURITY_ENDPOINT_URL = "https://bugzilla.mozilla.org/rest/bug?resolution=FIXED&bug_status=RESOLVED&bug_status=VERIFIED&bug_status=CLOSED&product=Firefox&query_format=advanced&classification=Client%20Software&classification=Developer%20Infrastructure&classification=Components&classification=Server%20Software&classification=Other&component=Security&component=Security%20Alerts&component=Security%20Assurance&component=Security%20Assurance%3A%20Applications&component=Security%20Assurance%3A%20Review%20Request&component=Security%20Block-lists%2C%20Allow-lists%2C%20and%20other%20State&component=Security%3A%20CAPS&component=Security%3A%20iOS&component=Security%3A%20OpenPGP&component=Security%3A%20OTR&component=Security%3A%20Process%20Sandboxing&component=Security%3A%20PSM&component=Security%3A%20RLBox&component=Security%3A%20S%2FMIME&limit="
BASE_HEADERS = {
    "X-BUGZILLA-API-KEY": "PzSsvL0XD4JKO1uJBegEAJPHGrB45zLDoLzBXPVp"
}
FILE_PATH = "E:\CTI\IV\Projects\output.txt"

class Bug:
    def __init__(self, summary, component, severity, creation_time, cf_last_resolved, time_diff):
        self.summary = summary
        self.component = component
        self.severity = severity
        self.creation_time = creation_time
        self.cf_last_resolved = cf_last_resolved
        self.time_diff = time_diff

def main():
    # fetch_responses_into_file()
    read_responses_from_file()

def fetch_responses_into_file():
    with open(FILE_PATH, "w", encoding="utf-8") as f:
        for offset in range(36000, MAX_OFFSET-LIMIT, LIMIT):
            print("Limit: " + str(LIMIT) + ", Offset: " + str(offset))
            response = requests.get(url=ENDPOINT_URL + str(LIMIT) + "&offset=" + str(offset), headers=BASE_HEADERS)
            response_json = response.json()

            if "bugs" in response_json:
                bugs = response_json["bugs"]

                for bug in bugs:
                    try:
                        f.write(bug["summary"] + ";;" + bug["component"] + ";;" + bug["severity"] + ";;" + bug["creation_time"] + ";;" + bug["cf_last_resolved"] + ";;" + str(make_difference(bug["creation_time"], bug["cf_last_resolved"])) + "\n")
                    except:
                        print("There was a problem with writing an input to the file.")

                f.flush()
            else:
                print("Key 'bugs' was not found in response")

def read_responses_from_file():
    bugs = []

    with open(FILE_PATH, "r", encoding="utf-8") as f:
        line = f.readline()

        while line:
            line_split = line.split(";;")

            if (line_split[1][0] == ';'):
                line_split[1] = line_split[1][1:]

            if (line_split[5][-1] == '\n'):
                line_split[5] = line_split[5][:-1]

            bug = Bug(line_split[0], line_split[1], line_split[2], line_split[3], line_split[4], int(line_split[5]))
            bugs.append(bug)
            line = f.readline()

    create_dataframe(bugs)

def make_difference(created_at, closed_at):
    time1 = datetime.strptime(created_at, "%Y-%m-%dT%H:%M:%SZ")
    time2 = datetime.strptime(closed_at, "%Y-%m-%dT%H:%M:%SZ")
    
    difference = time2 - time1
    return difference.days

def create_dataframe(bug_list):
    component_list = []    
    severity_list = []
    creation_time_list = []
    time_diff_list = []

    for bug in bug_list:
        component_list.append(bug.component)
        severity_list.append(bug.severity)
        creation_time_list.append(bug.creation_time)
        time_diff_list.append(bug.time_diff)

    data = {
        'component': component_list,
        'severity': severity_list,
        'creation_time': creation_time_list,
        'time_diff': time_diff_list
    }

    df = pd.DataFrame(data)
    df = df.sort_values(by="creation_time")

    df = perform_data_cleaning(df)

    plot_severity_counts(df)
    # plot_average_resolution_time(df)
    # plot_component_counts(df)
    # plot_component_resolution_time(df)
    # plot_distribution_over_time(df)

def perform_data_cleaning(df):
    df = df.drop(df[df['severity'] == '--'].index)
    df = df.drop(df[df['severity'] == 'N/A'].index)
    df = df.drop(df[df['component'] == 'Headless'].index)
    df = df.drop(df[df['component'] == 'System Add-ons: Off-train Deployment'].index)
    df = df.drop(df[df['component'] == 'Foxfooding'].index)
    df = df.drop(df[df['component'] == 'Normandy Server'].index)
    df = df.drop(df[df['component'] == 'Untriaged'].index)
    df = df.drop(df[df['component'] == 'about:logins'].index)
    df = df.drop(df[df['component'] == 'Nimbus Desktop Client'].index)
    df = df.drop(df[df['component'] == 'Tours'].index)
    df = df.drop(df[df['component'] == 'Distributions'].index)
    df = df.drop(df[df['component'] == 'Pioneer'].index)
    df = df.drop(df[df['component'] == 'WebPayments UI'].index)
    df = df.drop(df[df['component'] == 'Launcher Process'].index)
    df = df.drop(df[df['component'] == 'Enterprise Policies'].index)
    df = df.drop(df[df['component'] == 'Firefox Monitor'].index)
    df = df.drop(df[df['component'] == 'Normandy Client'].index)
    df = df.drop(df[df['component'] == 'Site Identity'].index)
    df = df.drop(df[df['component'] == 'Screenshots'].index)
    df = df.drop(df[df['component'] == 'Protections UI'].index)
    df = df.drop(df[df['component'] == 'Page Info Window'].index)
    df = df.drop(df[df['component'] == 'Sync'].index)
    df = df.drop(df[df['component'] == 'Toolbars and Customization'].index)
    df = df.drop(df[df['component'] == 'Remote Settings Client'].index)
    df = df.drop(df[df['component'] == 'Pocket'].index)
    df = df.drop(df[df['component'] == 'Disability Access'].index)
    df = df.drop(df[df['component'] == 'Extension Compatibility'].index)
    df = df.drop(df[df['component'] == 'Menus'].index)
    df = df.drop(df[df['component'] == 'Search'].index)
    df = df.drop(df[df['component'] == 'Session Restore'].index)
    df = df.drop(df[df['component'] == 'Migration'].index)
    df = df.drop(df[df['component'] == 'Data Loss Prevention'].index)
    df = df.drop(df[df['component'] == 'Shell Integration'].index)
    df = df.drop(df[df['component'] == 'Firefox View'].index)

    return df

def plot_severity_counts(df):
    df = df[df['component'] == 'Security']
    category_counts = df['severity'].value_counts()
    category_counts = category_counts.sort_index()
    category_counts.plot(kind='bar', color='skyblue', edgecolor='black')
    plt.title('Issue count for each severity type (Security)')
    plt.xlabel('Severity')
    plt.ylabel('Count')
    plt.xticks(rotation=30)
    plt.show()

def plot_average_resolution_time(df):
    average_values = df.groupby('severity')['time_diff'].mean()
    average_values.plot(kind='bar', color='skyblue', edgecolor='black')
    plt.title('Average resolution time for each severity')
    plt.xlabel('Severity type')
    plt.ylabel('Resolution time')
    plt.xticks(rotation=30)
    plt.show()

def plot_component_counts(df):
    category_counts = df['component'].value_counts()
    category_counts = category_counts.sort_index()
    category_counts.plot(kind='bar', color='skyblue', edgecolor='black')
    plt.title('Issue count for each component type')
    plt.xlabel('Component')
    plt.ylabel('Count')
    plt.xticks(rotation=30, fontsize=6)
    plt.show()

def plot_component_resolution_time(df):
    average_values = df.groupby('component')['time_diff'].mean()
    average_values.plot(kind='bar', color='skyblue', edgecolor='black')
    plt.title('Average resolution time for each component')
    plt.xlabel('Component type')
    plt.ylabel('Resolution time')
    plt.xticks(rotation=30, fontsize=6)
    plt.show()

def plot_distribution_over_time(df):
    df['creation_time_formatted'] = df['creation_time'].str[0:4]
    print(df)

    colormap = plt.get_cmap('tab20')

    num_components = len(df.columns)
    colors = colormap(np.linspace(0, 1, 20))

    df = df.groupby(['creation_time_formatted', 'component']).size().unstack(fill_value=0)
    df.plot(kind='bar', stacked=True, figsize=(10, 6), color=colors)
    plt.title('Distribution of Component Over Creation Date')
    plt.xlabel('Creation Date')
    plt.ylabel('Number of Issues')
    plt.xticks(rotation=45)
    plt.legend(title='Component')
    plt.tight_layout()
    plt.show()


if __name__ == "__main__":
    main()