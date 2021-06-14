pub const MESSAGE_1: &str = r##"{
  "key": "%/v5mCnV/kmnVtnF3zXtD4tbzoEQo4kRq/0d/bgxP1WI=.sha256",
  "value": {
    "previous": null,
    "author": "@U5GvOKP/YUza9k53DSXxT0mk3PIrnyAmessvNfZl5E0=.ed25519",
    "sequence": 1,
    "timestamp": 1470186877575,
    "hash": "sha256",
    "content": {
      "type": "about",
      "about": "@U5GvOKP/YUza9k53DSXxT0mk3PIrnyAmessvNfZl5E0=.ed25519",
      "name": "Piet"
    },
    "signature": "QJKWui3oyK6r5dH13xHkEVFhfMZDTXfK2tW21nyfheFClSf69yYK77Itj1BGcOimZ16pj9u3tMArLUCGSscqCQ==.sig.ed25519"
  },
  "timestamp": 1571140551481
}"##;

pub const MESSAGE_VALUE_1: &str = r##"{
  "previous": null,
  "author": "@U5GvOKP/YUza9k53DSXxT0mk3PIrnyAmessvNfZl5E0=.ed25519",
  "sequence": 1,
  "timestamp": 1470186877575,
  "hash": "sha256",
  "content": {
    "type": "about",
    "about": "@U5GvOKP/YUza9k53DSXxT0mk3PIrnyAmessvNfZl5E0=.ed25519",
    "name": "Piet"
  },
  "signature": "QJKWui3oyK6r5dH13xHkEVFhfMZDTXfK2tW21nyfheFClSf69yYK77Itj1BGcOimZ16pj9u3tMArLUCGSscqCQ==.sig.ed25519"
}"##;

pub const MESSAGE_1_INVALID_SEQ: &str = r##"{
  "key": "%/v5mCnV/kmnVtnF3zXtD4tbzoEQo4kRq/0d/bgxP1WI=.sha256",
  "value": {
    "previous": null,
    "author": "@U5GvOKP/YUza9k53DSXxT0mk3PIrnyAmessvNfZl5E0=.ed25519",
    "sequence": 0,
    "timestamp": 1470186877575,
    "hash": "sha256",
    "content": {
      "type": "about",
      "about": "@U5GvOKP/YUza9k53DSXxT0mk3PIrnyAmessvNfZl5E0=.ed25519",
      "name": "Piet"
    },
    "signature": "QJKWui3oyK6r5dH13xHkEVFhfMZDTXfK2tW21nyfheFClSf69yYK77Itj1BGcOimZ16pj9u3tMArLUCGSscqCQ==.sig.ed25519"
  },
  "timestamp": 1571140551481
}"##;

pub const MESSAGE_1_INVALID_PREVIOUS: &str = r##"{
  "key": "%/v5mCnV/kmnVtnF3zXtD4tbzoEQo4kRq/0d/bgxP1WI=.sha256",
  "value": {
    "previous": "%/v5mCnV/kmnVtnF3zXtD4tbzoEQo4kRq/0d/bgxP1WI=.sha256",
    "author": "@U5GvOKP/YUza9k53DSXxT0mk3PIrnyAmessvNfZl5E0=.ed25519",
    "sequence": 1,
    "timestamp": 1470186877575,
    "hash": "sha256",
    "content": {
      "type": "about",
      "about": "@U5GvOKP/YUza9k53DSXxT0mk3PIrnyAmessvNfZl5E0=.ed25519",
      "name": "Piet"
    },
    "signature": "QJKWui3oyK6r5dH13xHkEVFhfMZDTXfK2tW21nyfheFClSf69yYK77Itj1BGcOimZ16pj9u3tMArLUCGSscqCQ==.sig.ed25519"
  },
  "timestamp": 1571140551481
}"##;

pub const MESSAGE_2: &str = r##"{
  "key": "%kLWDux4wCG+OdQWAHnpBGzGlCehqMLfgLbzlKCvgesU=.sha256",
  "value": {
    "previous": "%/v5mCnV/kmnVtnF3zXtD4tbzoEQo4kRq/0d/bgxP1WI=.sha256",
    "author": "@U5GvOKP/YUza9k53DSXxT0mk3PIrnyAmessvNfZl5E0=.ed25519",
    "sequence": 2,
    "timestamp": 1470187292812,
    "hash": "sha256",
    "content": {
      "type": "about",
      "about": "@U5GvOKP/YUza9k53DSXxT0mk3PIrnyAmessvNfZl5E0=.ed25519",
      "image": {
        "link": "&MxwsfZoq7X6oqnEX/TWIlAqd6S+jsUA6T1hqZYdl7RM=.sha256",
        "size": 642763,
        "type": "image/png",
        "width": 512,
        "height": 512
      }
    },
    "signature": "j3C7Us3JDnSUseF4ycRB0dTMs0xC6NAriAFtJWvx2uyz0K4zSj6XL8YA4BVqv+AHgo08+HxXGrpJlZ3ADwNnDw==.sig.ed25519"
  },
  "timestamp": 1571140551485
}"##;

pub const MESSAGE_2_INVALID_ORDER: &str = r##"{
  "key": "%kLWDux4wCG+OdQWAHnpBGzGlCehqMLfgLbzlKCvgesU=.sha256",
  "value": {
    "previous": "%/v5mCnV/kmnVtnF3zXtD4tbzoEQo4kRq/0d/bgxP1WI=.sha256",
    "author": "@U5GvOKP/YUza9k53DSXxT0mk3PIrnyAmessvNfZl5E0=.ed25519",
    "sequence": 2,
    "hash": "sha256",
    "timestamp": 1470187292812,
    "content": {
      "type": "about",
      "about": "@U5GvOKP/YUza9k53DSXxT0mk3PIrnyAmessvNfZl5E0=.ed25519",
      "image": {
        "link": "&MxwsfZoq7X6oqnEX/TWIlAqd6S+jsUA6T1hqZYdl7RM=.sha256",
        "size": 642763,
        "type": "image/png",
        "width": 512,
        "height": 512
      }
    },
    "signature": "j3C7Us3JDnSUseF4ycRB0dTMs0xC6NAriAFtJWvx2uyz0K4zSj6XL8YA4BVqv+AHgo08+HxXGrpJlZ3ADwNnDw==.sig.ed25519"
  },
  "timestamp": 1571140551485
}"##;

pub const MESSAGE_VALUE_2: &str = r##"{
  "previous": "%/v5mCnV/kmnVtnF3zXtD4tbzoEQo4kRq/0d/bgxP1WI=.sha256",
  "author": "@U5GvOKP/YUza9k53DSXxT0mk3PIrnyAmessvNfZl5E0=.ed25519",
  "sequence": 2,
  "timestamp": 1470187292812,
  "hash": "sha256",
  "content": {
    "type": "about",
    "about": "@U5GvOKP/YUza9k53DSXxT0mk3PIrnyAmessvNfZl5E0=.ed25519",
    "image": {
      "link": "&MxwsfZoq7X6oqnEX/TWIlAqd6S+jsUA6T1hqZYdl7RM=.sha256",
      "size": 642763,
      "type": "image/png",
      "width": 512,
      "height": 512
    }
  },
  "signature": "j3C7Us3JDnSUseF4ycRB0dTMs0xC6NAriAFtJWvx2uyz0K4zSj6XL8YA4BVqv+AHgo08+HxXGrpJlZ3ADwNnDw==.sig.ed25519"
}"##;

pub const MESSAGE_3: &str = r##"{
  "key": "%VhHgLpaLfY/2/g4+WEhKv5DdXM1V1PCVW1u2kbkvTbY=.sha256",
  "value": {
    "previous": "%kLWDux4wCG+OdQWAHnpBGzGlCehqMLfgLbzlKCvgesU=.sha256",
    "author": "@U5GvOKP/YUza9k53DSXxT0mk3PIrnyAmessvNfZl5E0=.ed25519",
    "sequence": 3,
    "timestamp": 1470187303671,
    "hash": "sha256",
    "content": {
      "type": "contact",
      "contact": "@8HsIHUvTaWg8IXHpsb8dmDtKH8qLOrSNwNm298OkGoY=.ed25519",
      "following": true,
      "blocking": false
    },
    "signature": "PWhsT9c8HQMhJEohV0tF5mfSnZy0rU0CInnvah+whlMuYDQAjzpmW9be9X8eWVAsqbepS+5I7A7ttvwEonSaBg==.sig.ed25519"
  },
  "timestamp": 1571140551497
}"##;

pub const MESSAGE_2_PREVIOUS_NULL: &str = r##"{
  "key": "%kLWDux4wCG+OdQWAHnpBGzGlCehqMLfgLbzlKCvgesU=.sha256",
  "value": {
    "previous": null,
    "author": "@U5GvOKP/YUza9k53DSXxT0mk3PIrnyAmessvNfZl5E0=.ed25519",
    "sequence": 2,
    "timestamp": 1470187292812,
    "hash": "sha256",
    "content": {
      "type": "about",
      "about": "@U5GvOKP/YUza9k53DSXxT0mk3PIrnyAmessvNfZl5E0=.ed25519",
      "image": {
        "link": "&MxwsfZoq7X6oqnEX/TWIlAqd6S+jsUA6T1hqZYdl7RM=.sha256",
        "size": 642763,
        "type": "image/png",
        "width": 512,
        "height": 512
      }
    },
    "signature": "j3C7Us3JDnSUseF4ycRB0dTMs0xC6NAriAFtJWvx2uyz0K4zSj6XL8YA4BVqv+AHgo08+HxXGrpJlZ3ADwNnDw==.sig.ed25519"
  },
  "timestamp": 1571140551485
}"##;

//This message will not hash correctly AND would fail signature verification. But an attacker
//could publish a message that had correct hashes and signatures.
pub const MESSAGE_2_INCORRECT_AUTHOR: &str = r##"{
  "key": "%kLWDux4wCG+OdQWAHnpBGzGlCehqMLfgLbzlKCvgesU=.sha256",
  "value": {
    "previous": "%/v5mCnV/kmnVtnF3zXtD4tbzoEQo4kRq/0d/bgxP1WI=.sha256",
    "author": "@xzSRT0HSAqGuqu5HxJvqxtp2FJGpt5nRPIHMznLoBao=.ed25519",
    "sequence": 2,
    "timestamp": 1470187292812,
    "hash": "sha256",
    "content": {
      "type": "about",
      "about": "@U5GvOKP/YUza9k53DSXxT0mk3PIrnyAmessvNfZl5E0=.ed25519",
      "image": {
        "link": "&MxwsfZoq7X6oqnEX/TWIlAqd6S+jsUA6T1hqZYdl7RM=.sha256",
        "size": 642763,
        "type": "image/png",
        "width": 512,
        "height": 512
      }
    },
    "signature": "j3C7Us3JDnSUseF4ycRB0dTMs0xC6NAriAFtJWvx2uyz0K4zSj6XL8YA4BVqv+AHgo08+HxXGrpJlZ3ADwNnDw==.sig.ed25519"
  },
  "timestamp": 1571140551485
}"##;

pub const MESSAGE_2_INCORRECT_SEQUENCE: &str = r##"{
  "key": "%kLWDux4wCG+OdQWAHnpBGzGlCehqMLfgLbzlKCvgesU=.sha256",
  "value": {
    "previous": "%/v5mCnV/kmnVtnF3zXtD4tbzoEQo4kRq/0d/bgxP1WI=.sha256",
    "author": "@U5GvOKP/YUza9k53DSXxT0mk3PIrnyAmessvNfZl5E0=.ed25519",
    "sequence": 3,
    "timestamp": 1470187292812,
    "hash": "sha256",
    "content": {
      "type": "about",
      "about": "@U5GvOKP/YUza9k53DSXxT0mk3PIrnyAmessvNfZl5E0=.ed25519",
      "image": {
        "link": "&MxwsfZoq7X6oqnEX/TWIlAqd6S+jsUA6T1hqZYdl7RM=.sha256",
        "size": 642763,
        "type": "image/png",
        "width": 512,
        "height": 512
      }
    },
    "signature": "j3C7Us3JDnSUseF4ycRB0dTMs0xC6NAriAFtJWvx2uyz0K4zSj6XL8YA4BVqv+AHgo08+HxXGrpJlZ3ADwNnDw==.sig.ed25519"
  },
  "timestamp": 1571140551485
}"##;

pub const MESSAGE_2_INCORRECT_KEY: &str = r##"{
  "key": "%KLWDux4wCG+OdQWAHnpBGzGlCehqMLfgLbzlKCvgesU=.sha256",
  "value": {
    "previous": "%/v5mCnV/kmnVtnF3zXtD4tbzoEQo4kRq/0d/bgxP1WI=.sha256",
    "author": "@U5GvOKP/YUza9k53DSXxT0mk3PIrnyAmessvNfZl5E0=.ed25519",
    "sequence": 2,
    "timestamp": 1470187292812,
    "hash": "sha256",
    "content": {
      "type": "about",
      "about": "@U5GvOKP/YUza9k53DSXxT0mk3PIrnyAmessvNfZl5E0=.ed25519",
      "image": {
        "link": "&MxwsfZoq7X6oqnEX/TWIlAqd6S+jsUA6T1hqZYdl7RM=.sha256",
        "size": 642763,
        "type": "image/png",
        "width": 512,
        "height": 512
      }
    },
    "signature": "j3C7Us3JDnSUseF4ycRB0dTMs0xC6NAriAFtJWvx2uyz0K4zSj6XL8YA4BVqv+AHgo08+HxXGrpJlZ3ADwNnDw==.sig.ed25519"
  },
  "timestamp": 1571140551485
}"##;

pub const MESSAGE_2_FORK: &str = r##"{
  "key": "%kLWDux4wCG+OdQWAHnpBGzGlCehqMLfgLbzlKCvgesU=.sha256",
  "value": {
    "previous": "%/V5mCnV/kmnVtnF3zXtD4tbzoEQo4kRq/0d/bgxP1WI=.sha256",
    "author": "@U5GvOKP/YUza9k53DSXxT0mk3PIrnyAmessvNfZl5E0=.ed25519",
    "sequence": 2,
    "timestamp": 1470187292812,
    "hash": "sha256",
    "content": {
      "type": "about",
      "about": "@U5GvOKP/YUza9k53DSXxT0mk3PIrnyAmessvNfZl5E0=.ed25519",
      "image": {
        "link": "&MxwsfZoq7X6oqnEX/TWIlAqd6S+jsUA6T1hqZYdl7RM=.sha256",
        "size": 642763,
        "type": "image/png",
        "width": 512,
        "height": 512
      }
    },
    "signature": "j3C7Us3JDnSUseF4ycRB0dTMs0xC6NAriAFtJWvx2uyz0K4zSj6XL8YA4BVqv+AHgo08+HxXGrpJlZ3ADwNnDw==.sig.ed25519"
  },
  "timestamp": 1571140551485
}"##;

pub const MESSAGE_WITH_UNICODE: &str = r##"{
  "key": "%lYAK7Lfigw00zMt/UtVg5Ol9XdR4BHWUCxq4r2Ops90=.sha256",
  "value": {
    "previous": "%yV9QaYDbkEHl4W8S8hVf/3TUuvs0JUrOP945jLLK/2c=.sha256",
    "author": "@vt8uK0++cpFioCCBeB3p3jdx4RIdQYJOL/imN1Hv0Wk=.ed25519",
    "sequence": 36,
    "timestamp": 1445502075082,
    "hash": "sha256",
    "content": {
      "type": "post",
      "text": "Web frameworks.\n\n    Much industrial production in the late nineteenth century depended on skilled workers, whose knowledge of the production process often far exceeded their employers’; Taylor saw that this gave laborers a tremendous advantage over their employer in the struggle over the pace of work.\n\n    Not only could capitalists not legislate techniques they were ignorant of, but they were also in no position to judge when workers told them the process simply couldn’t be driven any faster. Work had to be redesigned so that employers did not depend on their employees for knowledge of the production process.\n\nhttps://www.jacobinmag.com/2015/04/braverman-gramsci-marx-technology/"
    },
    "signature": "FbDXlQtC2FQukU8svM5dOALN6QpxFhUHZaC7jTSXdOH7yqDfUlaj8q97YLdo5YqknZ71b0Y59hlQkmfkbtv5DA==.sig.ed25519"
  },
  "timestamp": 1571140555382.0059
}"##;

pub const MESSAGE_WITH_UNICODE_PREV: &str = r##"{
  "key": "%yV9QaYDbkEHl4W8S8hVf/3TUuvs0JUrOP945jLLK/2c=.sha256",
  "value": {
    "previous": "%fG8VUZqsl1034p8W+q3vFggEB074qj0hmRPamqq5TH4=.sha256",
    "author": "@vt8uK0++cpFioCCBeB3p3jdx4RIdQYJOL/imN1Hv0Wk=.ed25519",
    "sequence": 35,
    "timestamp": 1445499413793,
    "hash": "sha256",
    "content": {
      "type": "post",
      "text": "something non-linear is happening between 15 and 20 nodes [results.txt](&cwcDjgpJoPG1vjICsTutqfBi1gpNPa8ggl4fep1qCXc=.sha256)",
      "mentions": [
        {
          "link": "&cwcDjgpJoPG1vjICsTutqfBi1gpNPa8ggl4fep1qCXc=.sha256"
        }
      ]
    },
    "signature": "9Dh6hj/gdrruYNh/rkELEJrk0+quhQF1VfU7veJ8Yb/cDUHzaQWue2YljRuERThlyd+92cOfA4PujfNC2VbTDA==.sig.ed25519"
  },
  "timestamp": 1571140555382.002
}"##;

pub const MESSAGE_WITHOUT_HASH_FUNCTION: &str = r##"{
  "key": "%8Y0PR6EAoyObJhJZf2YQNn5B3RaCDzsrVrj2XxgRPhE=.sha256",
  "value": {
    "previous": null,
    "author": "@AzvddyStfk/T95/3VuHxuJRwqqpBkCyoW7qHRCui2N4=.ed25519",
    "sequence": 1,
    "timestamp": 1491901740000,
    "content": {
      "type": "invalid"
    },
    "signature": "sI9Nhe0HRC/W0q1DrgB4t0gkuBXLdgU6JMwZS59d6ZAitbF12H+6u9vXnE7ssikw4B4v+D0IvCSB2jRhXDICBw==.sig.ed25519"
    },
    "timestamp": 1571140555382.002
}"##;

pub const MESSAGE_WITH_INVALID_HASH_FUNCTION: &str = r##"{
  "key": "%nAzZR0XlsCzr1yb/jrSOAKGEol0cST0XMB3LYfPJheA=.sha256",
  "value": {
    "previous": null,
    "author": "@AzvddyStfk/T95/3VuHxuJRwqqpBkCyoW7qHRCui2N4=.ed25519",
    "sequence": 1,
    "timestamp": 1491901740000,
    "hash": "oanteuhnoatehuneotuh",
    "content": {
      "type": "invalid"
    },
    "signature": "9OAbsQs2qhSLhjKH6DRoJepk/pMLnyFux87Xm+Oz4otTwocYdKeXZuHMj+6tzZJ7jzYpqNmh8sQ/vTtRCUFZCg==.sig.ed25519"
  },
  "timestamp": 1571140555382.002
}"##;

pub const MESSAGE_WITH_EXTRA_FIELD: &str = r##"{
  "key": "%aR6KXa2nhQicxWGOv3ECWjUeysve/0p1HTAGmnt7u2w=.sha256",
  "value": {
    "previous": null,
    "author": "@AzvddyStfk/T95/3VuHxuJRwqqpBkCyoW7qHRCui2N4=.ed25519",
    "sequence": 1,
    "timestamp": 1491901740000,
    "hash": "sha256",
    "content": {
      "type": "invalid"
    },
    "signature": "tECMcZunn58MckGfUBL0GTqiy7Svfqs2Z+vgqxmdz5i5cjHg/WR4Glj1HX4B0ioSa+HeDyOBVG5s2HhXEEtUCQ==.sig.ed25519",
    "extra": "INVALID"
    },
  "timestamp": 1571140555382.002
}"##;

pub const MESSAGE_PRIVATE: &str = r##"{
  "key": "%uN9G3nZ+IYrCiC8Qmqb8J8hnefc486pZGeWyqBomAi8=.sha256",
  "value": {
    "previous": "%Z694dkKDUmNtoSwwjLG9cl7j0Dd26EDp0DRDmyPl1Lc=.sha256",
    "sequence": 24148,
    "author": "@iL6NzQoOLFP18pCpprkbY80DMtiG4JFFtVSVUaoGsOQ=.ed25519",
    "timestamp": 1620171292121,
    "hash": "sha256",
    "content": "siZEm1zFx1icq0SrEynGDpNRmJCXMxTB3iEteXFn+IhJH8WhMbT8tp9qOIaFkIYcdOyerSon6RK0l4RE1ZdDh/3lcGZSdP0Ljq59qsdqlf2ngwbIbV9AWdPRrPsoVZBV6RhI+YcVTloWWP5aauu1hZKjcm62ezLBTQ3EmFPYtDuwsOFkx9/7FP97ljhj67CwvlGzuiWp6FNICHbt5kOCxs9H0k6Tr8JJVdaJtJ2pqkX4p0ECMuEuYxCYbh3FpncCqlNZJXb0dj3iSsfsMNWTJLDqfkqJKH1jBVfxDL6+xAXBDS+E4F2hD4y9gRDZEej99uVBQWlbxr5eCRV+VbfBGYxwoAYtqux6rg3jBabImKKinBwHShEP5F/+wlb9IxQn4swyOgyv+UKx/jbx+91Ayso5bnNPZMpwRRX5p5DbpK1BnryeVJhktMgFqgni1g0lHyU8sQ2QzwZgXGw7dfYoamkqK4D24NOLnUoHuVuhd7Q5SxZWSAO6wpDa4nrODePoJdl328pbMwCoQlUNeHINmKxh/o/oCNbgXitn4oN3kSVEg/umdgwwI94gmZUjiYwP1v7HA7dI.box",
    "signature": "n4Wepa4fxq+xLlmfCxwiC489rMZlnnrBFOkWMuGAv80O7GK0XZUn1zfuCP9fQBab1+P0m1g+OLiyWwqHnwdTBw==.sig.ed25519"
    },
  "timestamp": 1620198134771
}"##;

pub const MESSAGE_PRIVATE_PREV: &str = r##"{
  "key": "%Z694dkKDUmNtoSwwjLG9cl7j0Dd26EDp0DRDmyPl1Lc=.sha256",
  "value": {
    "previous": "%cN1F3DkKC3bfxZlwWY98xqzsoQGEC9sRNe9HYm6khhk=.sha256",
    "sequence": 24147,
    "author": "@iL6NzQoOLFP18pCpprkbY80DMtiG4JFFtVSVUaoGsOQ=.ed25519",
    "timestamp": 1620136240655,
    "hash": "sha256",
    "content": {
      "type": "vote",
      "vote": {
        "link": "%SXw+GJZZBvS7neNDfuyu2UXmGD3Gl8jMxX2PPc7sjCs=.sha256",
        "value": 1,
        "expression": "Like"
      }
    },
    "signature": "iA958Ct3+9Z3tZZcbXvF4BAFVPJZ8MhfqnWOgzwhLdviL1KE3xTKn4joJl1a+mnqSLHbH/QT3NHQu378GdsHBg==.sig.ed25519"
    },
  "timestamp": 1620137278131.001
}"##;

pub const MESSAGE_PRIVATE_INVALID: &str = r##"{
  "key": "%uN9G3nZ+IYrCiC8Qmqb8J8hnefc486pZGeWyqBomAi8=.sha256",
  "value": {
    "previous": "%Z694dkKDUmNtoSwwjLG9cl7j0Dd26EDp0DRDmyPl1Lc=.sha256",
    "sequence": 24148,
    "author": "@iL6NzQoOLFP18pCpprkbY80DMtiG4JFFtVSVUaoGsOQ=.ed25519",
    "timestamp": 1620171292121,
    "hash": "sha256",
    "content": "==siZEm1zFx1icq0SrEynGDpNRmJCXMxTB3iEteXFn+IhJH8WhMbT8tp9qOIaFkIYcdOyerSon6RK0l4RE1ZdDh/3lcGZSdP0Ljq59qsdqlf2ngwbIbV9AWdPRrPsoVZBV6RhI+YcVTloWWP5aauu1hZKjcm62ezLBTQ3EmFPYtDuwsOFkx9/7FP97ljhj67CwvlGzuiWp6FNICHbt5kOCxs9H0k6Tr8JJVdaJtJ2pqkX4p0ECMuEuYxCYbh3FpncCqlNZJXb0dj3iSsfsMNWTJLDqfkqJKH1jBVfxDL6+xAXBDS+E4F2hD4y9gRDZEej99uVBQWlbxr5eCRV+VbfBGYxwoAYtqux6rg3jBabImKKinBwHShEP5F/+wlb9IxQn4swyOgyv+UKx/jbx+91Ayso5bnNPZMpwRRX5p5DbpK1BnryeVJhktMgFqgni1g0lHyU8sQ2QzwZgXGw7dfYoamkqK4D24NOLnUoHuVuhd7Q5SxZWSAO6wpDa4nrODePoJdl328pbMwCoQlUNeHINmKxh/o/oCNbgXitn4oN3kSVEg/umdgwwI94gmZUjiYwP1v7HA7dI.box",
    "signature": "n4Wepa4fxq+xLlmfCxwiC489rMZlnnrBFOkWMuGAv80O7GK0XZUn1zfuCP9fQBab1+P0m1g+OLiyWwqHnwdTBw==.sig.ed25519"
    },
  "timestamp": 1620198134771
}"##;
