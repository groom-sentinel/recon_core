"""Pipeline entry point: initialise DB schema and run the full recon pipeline."""

from pipeline.repository import MySQLPipelineRepository


def main() -> None:
    repo = MySQLPipelineRepository()
    repo.init_schema()
    print("DB schema initialised. Pipeline ready.")


if __name__ == "__main__":
    main()
