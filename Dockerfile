# Use slim Python image
FROM python:3.12-slim AS builder

WORKDIR /build

# Copy source
COPY agentsec/ agentsec/
COPY README.md pyproject.toml LICENSE ./

# Build and install into a copyable prefix
RUN pip install --no-cache-dir --prefix=/install .

FROM python:3.12-slim AS runtime

WORKDIR /app

# Copy only the installed package and console scripts from the builder stage.
COPY --from=builder /install /usr/local

# Entry point
ENTRYPOINT ["agentsec"]
CMD ["--help"]
