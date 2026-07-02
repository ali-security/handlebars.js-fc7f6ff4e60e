describe('compiler', function() {
  if (!Handlebars.compile) {
    return;
  }

  describe('#equals', function() {
    function compile(string) {
      var ast = Handlebars.parse(string);
      return new Handlebars.Compiler().compile(ast, {});
    }

    it('should treat as equal', function() {
      equal(compile('foo').equals(compile('foo')), true);
      equal(compile('{{foo}}').equals(compile('{{foo}}')), true);
      equal(compile('{{foo.bar}}').equals(compile('{{foo.bar}}')), true);
      equal(compile('{{foo.bar baz "foo" true false bat=1}}').equals(compile('{{foo.bar baz "foo" true false bat=1}}')), true);
      equal(compile('{{foo.bar (baz bat=1)}}').equals(compile('{{foo.bar (baz bat=1)}}')), true);
      equal(compile('{{#foo}} {{/foo}}').equals(compile('{{#foo}} {{/foo}}')), true);
    });
    it('should treat as not equal', function() {
      equal(compile('foo').equals(compile('bar')), false);
      equal(compile('{{foo}}').equals(compile('{{bar}}')), false);
      equal(compile('{{foo.bar}}').equals(compile('{{bar.bar}}')), false);
      equal(compile('{{foo.bar baz bat=1}}').equals(compile('{{foo.bar bar bat=1}}')), false);
      equal(compile('{{foo.bar (baz bat=1)}}').equals(compile('{{foo.bar (bar bat=1)}}')), false);
      equal(compile('{{#foo}} {{/foo}}').equals(compile('{{#bar}} {{/bar}}')), false);
      equal(compile('{{#foo}} {{/foo}}').equals(compile('{{#foo}} {{foo}}{{/foo}}')), false);
    });
  });

  describe('#compile', function() {
    it('should fail with invalid input', function() {
      shouldThrow(function() {
        Handlebars.compile(null);
      }, Error, 'You must pass a string or Handlebars AST to Handlebars.compile. You passed null');
      shouldThrow(function() {
        Handlebars.compile({});
      }, Error, 'You must pass a string or Handlebars AST to Handlebars.compile. You passed [object Object]');
    });

    it('can utilize AST instance', function() {
      equal(Handlebars.compile({
        type: 'Program',
        body: [ {type: 'ContentStatement', value: 'Hello'}]
      })(), 'Hello');
    });

    it('should reject AST with invalid PathExpression depth', function() {
      shouldThrow(function() {
        Handlebars.compile({
          type: 'Program',
          body: [
            {
              type: 'MustacheStatement',
              escaped: true,
              strip: { open: false, close: false },
              path: {
                type: 'PathExpression',
                data: false,
                depth: '0',
                parts: ['this'],
                original: 'this'
              },
              params: []
            }
          ]
        })();
      }, Error, 'Invalid AST: PathExpression.depth must be an integer');
    });

    it('should reject AST with non-array PathExpression parts', function() {
      shouldThrow(function() {
        Handlebars.compile({
          type: 'Program',
          body: [
            {
              type: 'MustacheStatement',
              escaped: true,
              strip: { open: false, close: false },
              path: {
                type: 'PathExpression',
                data: false,
                depth: 0,
                parts: 'this',
                original: 'this'
              },
              params: []
            }
          ]
        })();
      }, Error, 'Invalid AST: PathExpression.parts must be an array');
    });

    it('should reject AST with non-string PathExpression part', function() {
      shouldThrow(function() {
        Handlebars.compile({
          type: 'Program',
          body: [
            {
              type: 'MustacheStatement',
              escaped: true,
              strip: { open: false, close: false },
              path: {
                type: 'PathExpression',
                data: false,
                depth: 0,
                parts: [1],
                original: 'this'
              },
              params: []
            }
          ]
        })();
      }, Error, 'Invalid AST: PathExpression.parts must only contain strings');
    });

    it('should reject AST with invalid BooleanLiteral value type', function() {
      shouldThrow(function() {
        Handlebars.compile({
          type: 'Program',
          body: [
            {
              type: 'MustacheStatement',
              escaped: true,
              strip: { open: false, close: false },
              path: {
                type: 'PathExpression',
                data: false,
                depth: 0,
                parts: ['if'],
                original: 'if'
              },
              params: [
                {
                  type: 'BooleanLiteral',
                  value: 'true',
                  original: true
                }
              ]
            }
          ]
        })();
      }, Error, 'Invalid AST: BooleanLiteral.value must be a boolean');
    });

    it('should ignore loc metadata while validating AST nodes', function() {
      equal(Handlebars.compile({
        type: 'Program',
        meta: null,
        loc: { source: 'fake', start: { line: 1, column: 0 } },
        body: [{ type: 'ContentStatement', value: 'Hello' }]
      })(), 'Hello');
    });

    it('should accept AST with valid NumberLiteral values', function() {
      equal(Handlebars.compile(Handlebars.parse('{{lookup this 1}}'))(['a', 'b']), 'b');
    });

    it('should accept AST with valid BooleanLiteral values', function() {
      equal(Handlebars.compile(Handlebars.parse('{{#if true}}ok{{/if}}'))({}), 'ok');
    });

    it('can pass through an empty string', function() {
      equal(Handlebars.compile('')(), '');
    });
  });

  describe('#precompile', function() {
    it('should fail with invalid input', function() {
      shouldThrow(function() {
        Handlebars.precompile(null);
      }, Error, 'You must pass a string or Handlebars AST to Handlebars.precompile. You passed null');
      shouldThrow(function() {
        Handlebars.precompile({});
      }, Error, 'You must pass a string or Handlebars AST to Handlebars.precompile. You passed [object Object]');
    });

    it('can utilize AST instance', function() {
      equal(/return "Hello"/.test(Handlebars.precompile({
        type: 'Program',
        body: [ {type: 'ContentStatement', value: 'Hello'}]
      })), true);
    });

    it('can pass through an empty string', function() {
      equal(/return ""/.test(Handlebars.precompile('')), true);
    });
  });
});
