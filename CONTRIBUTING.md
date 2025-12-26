# Contributing to Snapshot Sleuth

Thank you for your interest in contributing to Snapshot Sleuth! This document provides guidelines for contributing to the project.

## Code of Conduct

By participating in this project, you agree to abide by our Code of Conduct (treat everyone with respect).

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/Snapshot-Sleuth.git`
3. Add upstream remote: `git remote add upstream https://github.com/Stealinglight/Snapshot-Sleuth.git`
4. Install dependencies: `pnpm install`
5. Build the project: `pnpm build`

## Development Workflow

### Creating a Branch

```bash
git checkout -b feature/your-feature-name
```

Use descriptive branch names:
- `feature/` for new features
- `fix/` for bug fixes
- `docs/` for documentation updates
- `refactor/` for code refactoring

### Making Changes

1. Write clean, maintainable code
2. Follow the existing code style
3. Add tests for new functionality
4. Update documentation as needed
5. Run linters: `pnpm lint`
6. Build the project: `pnpm build`

### Committing Changes

We use conventional commits:

```
type(scope): description

[optional body]

[optional footer]
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Test changes
- `chore`: Build process or tooling changes

Examples:
```
feat(adapters): add Jira case management adapter
fix(cdk): correct IAM policy for Lambda execution
docs(readme): update installation instructions
```

### Submitting a Pull Request

1. Push your changes: `git push origin feature/your-feature-name`
2. Open a pull request on GitHub
3. Provide a clear description of the changes
4. Link any related issues
5. Wait for review and address feedback

## Code Style

- Use TypeScript for all new code
- Follow ESLint and Prettier configurations
- Write self-documenting code with clear variable names
- Add JSDoc comments for public APIs
- Keep functions small and focused

## Testing

- Write unit tests for new functionality
- Ensure all tests pass: `pnpm test`
- Aim for high code coverage
- Test edge cases and error conditions

## Documentation

- Update README.md for user-facing changes
- Add inline comments for complex logic
- Update docs/ for architectural changes
- Include examples in documentation

## Adding a New Adapter

See the [Adapter Development Guide](./docs/adapters.md) for detailed instructions.

1. Create a new file in `packages/adapters/src/providers/`
2. Implement the required interface
3. Register in `AdapterFactory`
4. Add tests
5. Update documentation

## Project Structure

```
packages/
├── shared/        # Shared types and utilities
├── adapters/      # Integration adapters
├── cdk/           # Infrastructure as code
├── lambda-ts/     # TypeScript Lambda functions
├── lambda-py/     # Python Lambda functions
├── frontend/      # React frontend
└── demo/          # Demo environment
```

## Questions?

- Open a [Discussion](https://github.com/Stealinglight/Snapshot-Sleuth/discussions) for questions
- Check existing [Issues](https://github.com/Stealinglight/Snapshot-Sleuth/issues) before creating new ones
- Join our community chat (if available)

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
