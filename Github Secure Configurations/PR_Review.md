# Looking to enforce PR Reviews prior to merging?
## Use Github Global Rulesets!
Have your org admin create a managed ruleset for the org that requires 
- PR's in order to merge code
- Approval count is at least 1 (or your chosen number)
- Apply it to the default branch (or specify if you exclusively use a named branch for deploys)
- Set it to all repositories

## If you have exceptions you want to disable this for, you can apply Tags to repositories. 
Set up an organization tag for your given scope with a default value of "yes" (ie. PCI SCOPE) 
Manually toggle the tag to "no" for any excluded repositories. Setting this at the org level will require ord-admin privledges to edit the tag, so it is less likely to get altered. 
