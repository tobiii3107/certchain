import hashlib

from models import BlockchainRecord, db


GENESIS_PREVIOUS_HASH = "0" * 64


def calculate_block_hash(
    block_index,
    certificate_id,
    certificate_hash,
    previous_hash,
):
    block_data = (
        f"{block_index}|"
        f"{certificate_id}|"
        f"{certificate_hash}|"
        f"{previous_hash}"
    )

    return hashlib.sha256(
        block_data.encode("utf-8")
    ).hexdigest()


def create_blockchain_record(certificate):
    last_block = BlockchainRecord.query.order_by(
        BlockchainRecord.block_index.desc()
    ).first()

    if last_block is None:
        block_index = 1
        previous_hash = GENESIS_PREVIOUS_HASH
    else:
        block_index = last_block.block_index + 1
        previous_hash = last_block.block_hash

    block_hash = calculate_block_hash(
        block_index,
        certificate.id,
        certificate.blockchain_hash,
        previous_hash,
    )

    blockchain_record = BlockchainRecord(
        block_index=block_index,
        certificate_id=certificate.id,
        certificate_hash=certificate.blockchain_hash,
        previous_hash=previous_hash,
        block_hash=block_hash,
    )

    db.session.add(blockchain_record)

    return blockchain_record


def validate_blockchain():
    records = BlockchainRecord.query.order_by(
        BlockchainRecord.block_index.asc()
    ).all()

    expected_previous_hash = GENESIS_PREVIOUS_HASH
    expected_index = 1

    for record in records:
        expected_block_hash = calculate_block_hash(
            record.block_index,
            record.certificate_id,
            record.certificate_hash,
            record.previous_hash,
        )

        if record.block_index != expected_index:
            return False, record.block_index

        if record.previous_hash != expected_previous_hash:
            return False, record.block_index

        if record.block_hash != expected_block_hash:
            return False, record.block_index

        if record.certificate is None:
            return False, record.block_index

        if (
            record.certificate.blockchain_hash
            != record.certificate_hash
        ):
            return False, record.block_index

        expected_previous_hash = record.block_hash
        expected_index += 1

    return True, None