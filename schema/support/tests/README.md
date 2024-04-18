# All records in vald directory must validate:

$ node ../Node_validator/validate.js valid/*.json

  ...
  Summary: All files PASSED validation.

# All records in invald directory must fail to validate:

$ node ../Node_validator/validate.js invalid/*.json

  ....
  Summary: Validation FAILED for 5 out of 5 files!
