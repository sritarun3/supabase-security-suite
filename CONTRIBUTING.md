# Contributing to Supabase Security Suite

Thank you for your interest in contributing to the Supabase Security Suite! This document provides guidelines and information for contributors.

## 🚀 Getting Started

### Development Setup

1. **Fork and clone the repository**
```bash
git clone https://github.com/your-username/supabase-security-suite.git
cd supabase-security-suite
```

2. **Create a virtual environment**
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. **Install dependencies**
```bash
pip install -r requirements.txt
pip install -r requirements-dev.txt  # Development dependencies
```

4. **Run tests to ensure everything works**
```bash
python3 test_suite.py
```

## 🛠️ Development Guidelines

### Code Style

- Follow PEP 8 style guidelines
- Use meaningful variable and function names
- Add docstrings for all public functions and classes
- Keep functions focused and single-purpose

### Testing

- Write tests for new features
- Ensure all existing tests pass
- Aim for good test coverage
- Test both success and failure scenarios

### Documentation

- Update README.md for new features
- Add docstrings to new functions
- Update configuration examples
- Document breaking changes

## 🐛 Bug Reports

When reporting bugs, please include:

1. **Environment details**
   - Python version
   - Operating system
   - Supabase version (if applicable)

2. **Steps to reproduce**
   - Clear, numbered steps
   - Expected vs actual behavior

3. **Error messages**
   - Full traceback (if any)
   - Screenshots (if applicable)

4. **Additional context**
   - Configuration files (sanitized)
   - Sample code (if applicable)

## ✨ Feature Requests

For new features, please:

1. **Check existing issues** to avoid duplicates
2. **Describe the use case** clearly
3. **Explain the expected behavior**
4. **Consider security implications**
5. **Suggest implementation approach** (if you have ideas)

## 🔧 Pull Request Process

1. **Create a feature branch**
```bash
git checkout -b feature/your-feature-name
```

2. **Make your changes**
   - Write clean, tested code
   - Update documentation
   - Add tests for new functionality

3. **Test your changes**
```bash
python3 test_suite.py
python3 final.py --help  # Ensure CLI works
```

4. **Commit your changes**
```bash
git add .
git commit -m "Add: Brief description of changes"
```

5. **Push and create PR**
```bash
git push origin feature/your-feature-name
```

### PR Guidelines

- **Clear title**: Describe what the PR does
- **Detailed description**: Explain changes and reasoning
- **Link issues**: Reference any related issues
- **Screenshots**: For UI changes
- **Testing notes**: How to test the changes

## 🔒 Security Considerations

### When adding new security checks:

1. **Research thoroughly** - Understand the vulnerability
2. **Test carefully** - Ensure the check is accurate
3. **Document clearly** - Explain the risk and remediation
4. **Consider false positives** - Minimize noise in results

### For sensitive features:

1. **Default to secure** - Secure by default
2. **Document risks** - Clear warnings for dangerous operations
3. **Audit trails** - Log important operations
4. **User consent** - Get explicit confirmation for risky actions

## 🏗️ Architecture Guidelines

### Core Components

- **`final.py`**: Main scanning engine
- **`dashboard_server.py`**: Web dashboard
- **`templates/`**: HTML templates
- **`test_suite.py`**: Test runner

### Adding New Scanners

1. **Create scanner class** with consistent interface
2. **Implement required methods**:
   - `scan()`: Main scanning logic
   - `get_findings()`: Return results
3. **Add to main flow** in `final.py`
4. **Update dashboard** to display results

### Adding New Report Formats

1. **Extend `Finding` class** if needed
2. **Create formatter function**
3. **Add CLI option** for new format
4. **Update dashboard export** functionality

## 🧪 Testing Guidelines

### Test Categories

1. **Unit Tests**: Individual function testing
2. **Integration Tests**: Component interaction testing
3. **End-to-End Tests**: Full workflow testing
4. **Security Tests**: Vulnerability detection accuracy

### Test Structure

```python
def test_feature_name():
    """Test description."""
    # Arrange
    setup_test_data()
    
    # Act
    result = function_under_test()
    
    # Assert
    assert result.expected_behavior
```

### Test Data

- Use realistic but sanitized data
- Include edge cases and error conditions
- Avoid hardcoded secrets in test files

## 📚 Documentation Standards

### Code Documentation

```python
def scan_for_secrets(file_path: str) -> List[Finding]:
    """
    Scan a file for potential secret leaks.
    
    Args:
        file_path: Path to the file to scan
        
    Returns:
        List of Finding objects representing detected secrets
        
    Raises:
        FileNotFoundError: If the file doesn't exist
        PermissionError: If file access is denied
    """
```

### README Updates

- Keep installation instructions current
- Update feature lists for new capabilities
- Provide clear usage examples
- Document configuration options

## 🚀 Release Process

### Version Numbering

We follow [Semantic Versioning](https://semver.org/):
- **MAJOR**: Breaking changes
- **MINOR**: New features (backward compatible)
- **PATCH**: Bug fixes (backward compatible)

### Release Checklist

- [ ] All tests pass
- [ ] Documentation updated
- [ ] Changelog updated
- [ ] Version bumped
- [ ] Security review completed
- [ ] Release notes written

## 💬 Community Guidelines

### Communication

- Be respectful and constructive
- Ask questions if something is unclear
- Help others when you can
- Focus on the code, not the person

### Code Reviews

- Be thorough but constructive
- Explain your reasoning
- Suggest improvements
- Approve when satisfied

## 📞 Getting Help

- **GitHub Issues**: For bugs and feature requests
- **GitHub Discussions**: For questions and ideas
- **Discord/Slack**: For real-time chat (if available)

## 🙏 Recognition

Contributors will be recognized in:
- CONTRIBUTORS.md file
- Release notes
- Project documentation

Thank you for contributing to make Supabase more secure! 🔒