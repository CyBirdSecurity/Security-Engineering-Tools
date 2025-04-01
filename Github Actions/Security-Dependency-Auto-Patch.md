# Implementing Security-Dependency-Auto-Merge

## Setting up a label for your repo
If you keep in the label tagging feature, you will need to create the label. You can click on "Pull requests" in your repo and then "new label" in the top right corner.
<img width="1428" alt="Screenshot 2025-01-13 at 8 57 14 AM" src="https://github.com/user-attachments/assets/675170ab-9e33-40d9-af78-d60ed926247e" />
The label will need to match the workflow exactly, the default is "Dependency-Auto-Merge"

## Setting up auto-merge for your repo
You will need to go into your repo settings and ensure that Allow auto-merge is enabled.
<img width="813" alt="Screenshot 2025-01-22 at 8 51 53 AM" src="https://github.com/user-attachments/assets/07cde804-72fb-4a39-95fd-b32b49bfbbac" />

## Set up a service account. 
You'll need to create a service account that will be doing the approving for you. This service account will need to have read & write access to the repository as well as their PAT stored as a github action secret in the repo. The default name is "SECURITY_DEPENDENCY_AUTO_PATCH_PAT"
