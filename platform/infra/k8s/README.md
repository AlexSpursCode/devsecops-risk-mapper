# Kubernetes Notes

The current manifest in this directory deploys the API service.

For a production rollout, provision PostgreSQL, Neo4j, and object storage with managed operators/charts and inject these environment variables:

- `STORAGE_BACKEND=postgres`
- `DATABASE_URL`
- `NEO4J_URI`
- `NEO4J_USER`
- `NEO4J_PASSWORD`
- `OBJECT_STORE_ENDPOINT`
- `OBJECT_STORE_ACCESS_KEY`
- `OBJECT_STORE_SECRET_KEY`
- `OBJECT_STORE_BUCKET`
