# Contributing to PhishGuard AI

Thank you for your interest in contributing to PhishGuard AI! This document provides guidelines for contributing to the project.

## 🎯 Ways to Contribute

- **Report Bugs** - Found a bug? Open an issue
- **Suggest Features** - Have an idea? We'd love to hear it
- **Improve Documentation** - Help make our docs better
- **Submit Code** - Fix bugs or add features
- **Test** - Help test the application on different platforms

## 🚀 Getting Started

1. Fork the repository
2. Clone your fork:
   ```bash
   git clone https://github.com/YOUR_USERNAME/PhishGuard-AI-Real-Time-Phishing-Website-Detection.git
   ```
3. Create a new branch:
   ```bash
   git checkout -b feature/your-feature-name
   ```
4. Make your changes
5. Test your changes
6. Commit and push
7. Open a Pull Request

## 💻 Development Setup

### Backend Development
```bash
cd backend
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### Testing Your Changes
1. Train the model (if needed):
   ```bash
   python train_model.py
   ```
2. Start the server:
   ```bash
   python app.py
   ```
3. Test the API endpoints
4. Test the frontend

## 📝 Code Style

### Python (Backend)
- Follow PEP 8 guidelines
- Use meaningful variable names
- Add docstrings to functions
- Keep functions focused and small
- Handle errors appropriately

### JavaScript (Frontend)
- Use ES6+ features
- Use meaningful variable names
- Add comments for complex logic
- Follow consistent formatting

### HTML/CSS
- Use semantic HTML
- Keep CSS organized
- Maintain responsive design
- Follow existing style patterns

## 🧪 Testing

Before submitting a PR, ensure:
- [ ] All existing functionality still works
- [ ] New features are tested
- [ ] No console errors
- [ ] API endpoints return expected results
- [ ] Frontend displays correctly

## 📋 Pull Request Guidelines

1. **Title**: Clear and descriptive
2. **Description**: Explain what changes you made and why
3. **Testing**: Describe how you tested your changes
4. **Screenshots**: Include for UI changes
5. **Documentation**: Update docs if needed

### PR Checklist
- [ ] Code follows project style
- [ ] All tests pass
- [ ] Documentation updated
- [ ] No security vulnerabilities
- [ ] Commit messages are clear

## 🐛 Reporting Bugs

When reporting bugs, include:
- **Description**: What's the bug?
- **Steps to Reproduce**: How to trigger it?
- **Expected Behavior**: What should happen?
- **Actual Behavior**: What actually happens?
- **Environment**: OS, Python version, browser
- **Screenshots**: If applicable

## 💡 Suggesting Features

When suggesting features:
- **Use Case**: Why is this needed?
- **Description**: What should it do?
- **Implementation Ideas**: How might it work?
- **Alternatives**: Other approaches considered?

## 🔒 Security

Found a security vulnerability? Please **DO NOT** open a public issue. Instead, email the maintainers directly.

## 📜 Code of Conduct

- Be respectful and inclusive
- Welcome newcomers
- Accept constructive criticism
- Focus on what's best for the community

## 📧 Questions?

Have questions? Feel free to:
- Open an issue
- Start a discussion
- Contact the maintainers

## 🙏 Thank You!

Your contributions make PhishGuard AI better for everyone!

---

**Happy Contributing! 🎉**
