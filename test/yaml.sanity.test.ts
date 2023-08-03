
import YML from '../src/YML'

it("custom yaml tags...", async () => {
  const yourData = `
user_claims:
  data_types:
    - !sd null
    - !sd 42
    - !sd 3.14
    - !sd "foo"
    - !sd True
    - !sd ["Test"]  
    - !sd {"foo": "bar"}
`
  const result = YML.load(yourData);
  expect(result.user_claims).toBeDefined()
  // console.log(JSON.stringify(result, null, 2))
});

