"""Signature similarity model for tracking related signatures."""

from datetime import datetime
from sqlalchemy import Column, Integer, Float, String, DateTime, ForeignKey, UniqueConstraint, Index
from sqlalchemy.sql import func
from ..database import Base


class SignatureSimilarity(Base):
    """Store pre-computed similarity scores between signatures."""

    __tablename__ = "signature_similarities"

    id = Column(Integer, primary_key=True, index=True)
    signature_id_1 = Column(Integer, ForeignKey("signatures.id", ondelete="CASCADE"), nullable=False)
    signature_id_2 = Column(Integer, ForeignKey("signatures.id", ondelete="CASCADE"), nullable=False)
    similarity_score = Column(Float, nullable=False)
    similarity_type = Column(String(20), nullable=False)  # 'exact', 'substring', 'strings', 'hash'
    computed_at = Column(DateTime, default=func.now(), nullable=False)

    __table_args__ = (
        UniqueConstraint("signature_id_1", "signature_id_2", "similarity_type", name="uq_sig_similarity"),
        Index("idx_similarity_sig1", signature_id_1),
        Index("idx_similarity_sig2", signature_id_2),
        Index("idx_similarity_score", similarity_score.desc()),
    )
