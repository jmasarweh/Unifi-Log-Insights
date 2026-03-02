"""Saved views CRUD endpoints for Flow View filter presets."""

import logging

from fastapi import APIRouter, HTTPException
from psycopg2.extras import RealDictCursor, Json

from deps import get_conn, put_conn
from query_helpers import validate_view_filters

logger = logging.getLogger('api.views')

router = APIRouter()


@router.get("/api/views")
def list_views():
    """List all saved views ordered by created_at DESC."""
    conn = get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                "SELECT id, name, filters, created_at FROM saved_views "
                "ORDER BY created_at DESC"
            )
            views = []
            for row in cur.fetchall():
                v = dict(row)
                if v.get('created_at'):
                    v['created_at'] = v['created_at'].isoformat()
                views.append(v)
        conn.commit()
        return {"views": views}
    except Exception as e:
        conn.rollback()
        logger.exception("Error listing saved views")
        raise HTTPException(status_code=500, detail="Internal server error") from e
    finally:
        put_conn(conn)


@router.post("/api/views")
def create_view(body: dict):
    """Create a saved view with validated filters."""
    name = body.get('name', '')
    if isinstance(name, str):
        name = name.strip()
    if not name or not isinstance(name, str):
        raise HTTPException(status_code=400, detail="name is required")
    if len(name) > 100:
        raise HTTPException(status_code=400, detail="name must be 100 characters or less")

    filters = body.get('filters')
    if not filters:
        raise HTTPException(status_code=400, detail="filters is required")

    error = validate_view_filters(filters)
    if error:
        raise HTTPException(status_code=400, detail=error)

    conn = get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                "INSERT INTO saved_views (name, filters) VALUES (%s, %s) RETURNING id, name, filters, created_at",
                [name, Json(filters)]
            )
            row = dict(cur.fetchone())
            if row.get('created_at'):
                row['created_at'] = row['created_at'].isoformat()
        conn.commit()
        return row
    except Exception as e:
        conn.rollback()
        logger.exception("Error creating saved view")
        raise HTTPException(status_code=500, detail="Internal server error") from e
    finally:
        put_conn(conn)


@router.delete("/api/views/{view_id}")
def delete_view(view_id: int):
    """Delete a saved view by id."""
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM saved_views WHERE id = %s", [view_id])
            if cur.rowcount == 0:
                raise HTTPException(status_code=404, detail="View not found")
        conn.commit()
        return {"success": True}
    except HTTPException:
        conn.rollback()
        raise
    except Exception as e:
        conn.rollback()
        logger.exception("Error deleting saved view")
        raise HTTPException(status_code=500, detail="Internal server error") from e
    finally:
        put_conn(conn)
