describe('security issues', function() {
    describe('GH-1495: Prevent Remote Code Execution via constructor', function() {
        it('should not allow constructors to be accessed', function() {
            shouldCompileTo('{{constructor.name}}', {}, '');
            shouldCompileTo('{{lookup (lookup this "constructor") "name"}}', {}, '');
        });

        it('should allow the "constructor" property to be accessed if it is enumerable', function() {
            shouldCompileTo('{{constructor.name}}', {'constructor': {
                'name': 'here we go'
            }}, 'here we go');
            shouldCompileTo('{{lookup (lookup this "constructor") "name"}}', {'constructor': {
                'name': 'here we go'
            }}, 'here we go');
        });

        it('should allow prototype properties that are not constructors', function() {
            function TestClass() {
            }
            Object.defineProperty(TestClass.prototype, 'abc', {
                get: function() {
                    return 'xyz';
                }
            });
            shouldCompileTo('{{#with this as |obj|}}{{obj.abc}}{{/with}}',
                new TestClass(), 'xyz');
            shouldCompileTo('{{#with this as |obj|}}{{lookup obj "abc"}}{{/with}}',
                new TestClass(), 'xyz');

        });
    });

    describe('GH-1595: dangerous properties are not enumerable by default', function() {
        it('should not allow dangerous properties to be accessed directly', function() {
            shouldCompileTo('{{constructor}}', {}, '');
            shouldCompileTo('{{__defineGetter__}}', {}, '');
            shouldCompileTo('{{__defineSetter__}}', {}, '');
            shouldCompileTo('{{__lookupGetter__}}', {}, '');
            shouldCompileTo('{{__lookupSetter__}}', {}, '');
            shouldCompileTo('{{__proto__}}', {}, '');
        });

        it('should not allow dangerous properties to be accessed via the lookup-helper', function() {
            shouldCompileTo('{{lookup this "constructor"}}', {}, '');
            shouldCompileTo('{{lookup this "__defineGetter__"}}', {}, '');
            shouldCompileTo('{{lookup this "__defineSetter__"}}', {}, '');
            shouldCompileTo('{{lookup this "__lookupGetter__"}}', {}, '');
            shouldCompileTo('{{lookup this "__lookupSetter__"}}', {}, '');
            shouldCompileTo('{{lookup this "__proto__"}}', {}, '');
        });
    });

    describe('GH-1558: Prevent explicit call of helperMissing-helpers', function() {
        if (!Handlebars.compile) {
            return;
        }

        describe('without the option "allowExplicitCallOfHelperMissing"', function() {
            it('should throw an exception when calling  "{{helperMissing}}" ', function() {
                shouldThrow(function() {
                    var template = Handlebars.compile('{{helperMissing}}');
                    template({});
                }, Error);
            });
            it('should throw an exception when calling  "{{#helperMissing}}{{/helperMissing}}" ', function() {
                shouldThrow(function() {
                    var template = Handlebars.compile('{{#helperMissing}}{{/helperMissing}}');
                    template({});
                }, Error);
            });
            it('should throw an exception when calling  "{{blockHelperMissing "abc" .}}" ', function() {
                var functionCalls = [];
                shouldThrow(function() {
                    var template = Handlebars.compile('{{blockHelperMissing "abc" .}}');
                    template({ fn: function() { functionCalls.push('called'); }});
                }, Error);
                equals(functionCalls.length, 0);
            });
            it('should throw an exception when calling  "{{#blockHelperMissing .}}{{/blockHelperMissing}}"', function() {
                shouldThrow(function() {
                    var template = Handlebars.compile('{{#blockHelperMissing .}}{{/blockHelperMissing}}');
                    template({ fn: function() { return 'functionInData';}});
                }, Error);
            });
        });

        describe('with the option "allowCallsToHelperMissing" set to true', function() {
            it('should not throw an exception when calling  "{{helperMissing}}" ', function() {
                    var template = Handlebars.compile('{{helperMissing}}');
                    template({}, {allowCallsToHelperMissing: true});
            });
            it('should not throw an exception when calling  "{{#helperMissing}}{{/helperMissing}}" ', function() {
                    var template = Handlebars.compile('{{#helperMissing}}{{/helperMissing}}');
                    template({}, {allowCallsToHelperMissing: true});
            });
            it('should not throw an exception when calling  "{{blockHelperMissing "abc" .}}" ', function() {
                    var functionCalls = [];
                    var template = Handlebars.compile('{{blockHelperMissing "abc" .}}');
                    template({ fn: function() { functionCalls.push('called'); }}, {allowCallsToHelperMissing: true});
                    equals(functionCalls.length, 1);
            });
            it('should not throw an exception when calling  "{{#blockHelperMissing .}}{{/blockHelperMissing}}"', function() {
                    var template = Handlebars.compile('{{#blockHelperMissing true}}sdads{{/blockHelperMissing}}');
                    template({}, {allowCallsToHelperMissing: true});
            });
        });
    });

    describe('GH-1563', function() {
        it('should not allow to access constructor after overriding via __defineGetter__', function() {
            if (({}).__defineGetter__ == null || ({}).__lookupGetter__ == null) {
                return this.skip(); // Browser does not support this exploit anyway
            }
            shouldThrow(function() {
                shouldCompileTo('{{__defineGetter__ "undefined" valueOf }}' +
                    '{{#with __lookupGetter__ }}' +
                    '{{__defineGetter__ "propertyIsEnumerable" (this.bind (this.bind 1)) }}' +
                    '{{constructor.name}}' +
                    '{{/with}}', {}, '');
            }, Error, /Missing helper: "__defineGetter__"/);
        });
    });

    describe('GH-1633: Prevent access to dangerous properties in strict-mode', function() {
        var strictOptions = { strict: true };

        it('should not allow dangerous properties to be accessed as the terminal of a path', function() {
            shouldCompileTo('{{constructor}}', [{}, {}, {}, strictOptions], '');
            shouldCompileTo('{{__defineGetter__}}', [{}, {}, {}, strictOptions], '');
            shouldCompileTo('{{__defineSetter__}}', [{}, {}, {}, strictOptions], '');
            shouldCompileTo('{{__lookupGetter__}}', [{}, {}, {}, strictOptions], '');
            shouldCompileTo('{{__proto__}}', [{}, {}, {}, strictOptions], '');
        });

        it('should not allow dangerous properties to be accessed as a nested terminal', function() {
            shouldCompileTo('{{value.constructor}}', [{ value: {} }, {}, {}, strictOptions], '');
            shouldCompileTo('{{value.__proto__}}', [{ value: {} }, {}, {}, strictOptions], '');
        });
    });

    describe('escapes template variables', function() {
        it('in compat mode', function() {
            shouldCompileTo("{{'a\\b'}}", [{ 'a\\b': 'c' }, {}, {}, { compat: true }], 'c');
        });

        it('in default mode', function() {
            shouldCompileTo("{{'a\\b'}}", { 'a\\b': 'c' }, 'c');
        });

        it('in strict mode', function() {
            shouldCompileTo("{{'a\\b'}}", [{ 'a\\b': 'c' }, {}, {}, { strict: true }], 'c');
        });
    });

    describe('GHSA-2qvq-rjwj-gvw9: partial resolution must not use polluted prototypes', function() {
        if (!Handlebars.compile) {
            return;
        }

        afterEach(function() {
            delete Object.prototype.widget;
        });

        it('should not resolve partial names from Object.prototype', function() {
            Object.prototype.widget = '<img src=x onerror="alert(1)">'; // eslint-disable-line no-extend-native

            shouldThrow(function() {
                Handlebars.compile('<div>{{> widget}}</div>')({});
            }, Error, /could not be found/);
        });
    });

    describe('GHSA-2w6w-674q-4c4q, GHSA-xhpv-hc6g-r9c6, GHSA-3mfm-83xf-c92r: untrusted AST inputs', function() {
        if (!Handlebars.compile) {
            return;
        }

        function createInjectedProgram() {
            return {
                type: 'Program',
                body: [
                    {
                        type: 'MustacheStatement',
                        escaped: true,
                        strip: {
                            open: false,
                            close: false
                        },
                        path: {
                            type: 'PathExpression',
                            data: false,
                            depth: 0,
                            parts: ['lookup'],
                            original: 'lookup'
                        },
                        params: [
                            {
                                type: 'PathExpression',
                                data: false,
                                depth: 0,
                                parts: [],
                                original: 'this'
                            },
                            {
                                type: 'NumberLiteral',
                                value: '{},{})) + (Function) + (({}',
                                original: 1
                            }
                        ]
                    }
                ]
            };
        }

        it('should reject AST NumberLiteral type confusion in compile()', function() {
            shouldThrow(function() {
                var template = Handlebars.compile(createInjectedProgram());
                template({});
            }, Error, /Invalid AST/);
        });

        it('should reject AST objects passed via dynamic partial lookup', function() {
            shouldThrow(function() {
                var template = Handlebars.compile('{{> (lookup . "payload")}}');
                template({
                    payload: createInjectedProgram()
                });
            }, Error, /Invalid AST|could not be found/);
        });
    });

    describe('GHSA-442j-39wm-28r2: lookup must return checked value', function() {
        if (!Handlebars.compile) {
            return;
        }

        it('should use the validated value from lookupProperty() in compat mode', function() {
            var input = { child: {} };
            var readCount = 0;
            Object.defineProperty(input, 'unstable', {
                enumerable: true,
                get: function() {
                    readCount++;
                    return readCount === 1 ? 'first-read' : 'second-read';
                }
            });

            shouldCompileTo('{{#with child}}{{unstable}}{{/with}}', [input, {}, {}, { compat: true }], 'first-read');
        });
    });

    describe('GHSA-9cx6-37pm-9jff: malformed decorators should fail safely', function() {
        if (!Handlebars.compile) {
            return;
        }

        it('should throw a controlled error for unknown decorators', function() {
            var template = Handlebars.compile('{{*notRegistered}}');
            shouldThrow(function() {
                template({});
            }, Error, /Missing decorator|not registered/);
        });
    });

    describe('GHSA-new: @partial-block must not resolve from polluted prototype', function() {
        if (!Handlebars.compile) {
            return;
        }

        afterEach(function() {
            delete Object.prototype['partial-block'];
        });

        it('should not resolve @partial-block from Object.prototype', function() {
            Object.prototype['partial-block'] = '<img src=x onerror="alert(1)">'; // eslint-disable-line no-extend-native

            shouldThrow(function() {
                Handlebars.compile('{{> @partial-block}}')({});
            }, Error, /could not be found/);
        });

        it('should not resolve @partial-block from Object.prototype inside a partial', function() {
            Object.prototype['partial-block'] = '<img src=x onerror="alert(1)">'; // eslint-disable-line no-extend-native

            Handlebars.registerPartial('testPartial', '{{> @partial-block}}');
            try {
                shouldThrow(function() {
                    Handlebars.compile('{{> testPartial}}')({});
                }, Error, /could not be found/);
            } finally {
                Handlebars.unregisterPartial('testPartial');
            }
        });

        it('should still render legitimate @partial-block content', function() {
            Handlebars.registerPartial('wrapper', '<div>{{> @partial-block}}</div>');
            try {
                var result = Handlebars.compile('{{#> wrapper}}hello{{/wrapper}}')({});
                equal(result, '<div>hello</div>');
            } finally {
                Handlebars.unregisterPartial('wrapper');
            }
        });
    });
});
