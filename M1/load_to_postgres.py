import pandas as pd
from sqlalchemy import create_engine

engine = create_engine("postgresql+psycopg2://kestrel:kestrel_dev@localhost:5432/kestrel")

pd.read_csv("M1/data/fact_rejected_record.csv").to_sql(
    "fact_rejected_record", engine, if_exists="replace", index=False, chunksize=50000)
pd.read_csv("M1/data/model_pricing_clean.csv").to_sql(
    "model_pricing", engine, if_exists="replace", index=False)

canon = pd.read_parquet("M1/data/canonical_activity.parquet")
canon.to_sql("canonical_activity", engine, if_exists="replace", index=False,
             chunksize=50000, method="multi")
print("loaded")