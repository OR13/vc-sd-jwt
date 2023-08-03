
import jsyaml from 'js-yaml';

class SelectiveDisclosureTag {
  public type: any
  public data: any
  constructor(type: any, data: any) {
    this.type = type;
    this.data = data;
  }
}

const SelectiveDisclosureSchema = jsyaml.DEFAULT_SCHEMA.extend(['scalar', 'sequence', 'mapping'].map(function (kind) {
  return new jsyaml.Type('!sd', {
    kind: kind,
    multi: true,
    representName: function (object: any) {
      return object.type;
    },
    represent: function (object: any) {
      return object.data;
    },
    instanceOf: SelectiveDisclosureTag,
    construct: function (data: any, type: any) {
      return new SelectiveDisclosureTag(type, data);
    }
  });
}));

const load = (yourData: any) => jsyaml.load(yourData, { schema: SelectiveDisclosureSchema });

const api = { load }

export default api;