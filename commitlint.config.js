// Conventional Commits, restricted to the commit types this project uses (see CONTRIBUTING.md).
export default {
  extends: ['@commitlint/config-conventional'],
  rules: {
    'type-enum': [2, 'always', ['feat', 'fix', 'chore', 'docs', 'refactor', 'perf', 'test', 'ci', 'build']],
    'header-max-length': [2, 'always', 72],
  },
};
