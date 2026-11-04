/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */
import {
  collection,
  doc,
  getDocs,
  getDoc,
  setDoc,
  addDoc,
  updateDoc,
  deleteDoc,
  query,
  where,
  orderBy,
  limit,
  serverTimestamp,
  type DocumentData
} from 'firebase/firestore';
import { db, auth } from '../firebase';

export enum OperationType {
  CREATE = 'create',
  UPDATE = 'update',
  DELETE = 'delete',
  LIST = 'list',
  GET = 'get',
  WRITE = 'write',
}

export interface FirestoreErrorInfo {
  error: string;
  operationType: OperationType;
  path: string | null;
  authInfo: {
    userId?: string | null;
    email?: string | null;
    emailVerified?: boolean | null;
    isAnonymous?: boolean | null;
    tenantId?: string | null;
    providerInfo?: {
      providerId?: string | null;
      email?: string | null;
    }[];
  };
}

export function handleFirestoreError(error: unknown, operationType: OperationType, path: string | null): never {
  const errInfo: FirestoreErrorInfo = {
    error: error instanceof Error ? error.message : String(error),
    authInfo: {
      userId: auth.currentUser?.uid || null,
      email: auth.currentUser?.email || null,
      emailVerified: auth.currentUser?.emailVerified || null,
      isAnonymous: auth.currentUser?.isAnonymous || false,
      tenantId: auth.currentUser?.tenantId || null,
      providerInfo: auth.currentUser?.providerData?.map(provider => ({
        providerId: provider.providerId,
        email: provider.email,
      })) || []
    },
    operationType,
    path
  };
  console.error('Firestore Error: ', JSON.stringify(errInfo));
  throw new Error(JSON.stringify(errInfo));
}

export interface DetectionEventItem {
  id?: string;
  tenantId: string;
  cameraId: string;
  className: string;
  confidence: number;
  bbox?: number[];
  timestamp: string;
}

export interface IncidentItem {
  id?: string;
  tenantId: string;
  title: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  status: 'OPEN' | 'INVESTIGATING' | 'RESOLVED';
  cameraId?: string;
  details?: string;
  timestamp: string;
}

export interface PolicyItem {
  id?: string;
  tenantId: string;
  name: string;
  targetClass: string;
  condition: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  enabled: boolean;
  description?: string;
}

export interface AuditLogItem {
  id?: string;
  tenantId: string;
  action: string;
  actor: string;
  status: 'SUCCESS' | 'BLOCKED' | 'FAILED';
  details: string;
  timestamp: string;
}

// 1. Detection Events Service
export async function createDetectionEvent(event: DetectionEventItem): Promise<string> {
  const path = 'events';
  try {
    const docRef = await addDoc(collection(db, path), {
      ...event,
      createdAt: serverTimestamp()
    });
    return docRef.id;
  } catch (error) {
    handleFirestoreError(error, OperationType.CREATE, path);
  }
}

export async function listDetectionEvents(tenantId: string, maxItems: number = 20): Promise<DetectionEventItem[]> {
  const path = 'events';
  try {
    const q = query(
      collection(db, path),
      where('tenantId', '==', tenantId),
      orderBy('timestamp', 'desc'),
      limit(maxItems)
    );
    const snap = await getDocs(q);
    return snap.docs.map(d => ({ id: d.id, ...(d.data() as DetectionEventItem) }));
  } catch (error) {
    handleFirestoreError(error, OperationType.LIST, path);
  }
}

// 2. Incidents Service
export async function createIncident(incident: IncidentItem): Promise<string> {
  const path = 'incidents';
  try {
    const docRef = await addDoc(collection(db, path), {
      ...incident,
      createdAt: serverTimestamp()
    });
    return docRef.id;
  } catch (error) {
    handleFirestoreError(error, OperationType.CREATE, path);
  }
}

export async function listIncidents(tenantId: string): Promise<IncidentItem[]> {
  const path = 'incidents';
  try {
    const q = query(
      collection(db, path),
      where('tenantId', '==', tenantId),
      orderBy('timestamp', 'desc')
    );
    const snap = await getDocs(q);
    return snap.docs.map(d => ({ id: d.id, ...(d.data() as IncidentItem) }));
  } catch (error) {
    handleFirestoreError(error, OperationType.LIST, path);
  }
}

export async function resolveIncidentInFirestore(incidentId: string): Promise<void> {
  const path = `incidents/${incidentId}`;
  try {
    await updateDoc(doc(db, 'incidents', incidentId), {
      status: 'RESOLVED',
      resolvedAt: new Date().toISOString()
    });
  } catch (error) {
    handleFirestoreError(error, OperationType.UPDATE, path);
  }
}

// 3. Security Policies Service
export async function listPolicies(tenantId: string): Promise<PolicyItem[]> {
  const path = 'policies';
  try {
    const q = query(collection(db, path), where('tenantId', '==', tenantId));
    const snap = await getDocs(q);
    return snap.docs.map(d => ({ id: d.id, ...(d.data() as PolicyItem) }));
  } catch (error) {
    handleFirestoreError(error, OperationType.LIST, path);
  }
}

// 4. Audit Trail Service
export async function createAuditLog(log: AuditLogItem): Promise<string> {
  const path = 'audit';
  try {
    const docRef = await addDoc(collection(db, path), {
      ...log,
      createdAt: serverTimestamp()
    });
    return docRef.id;
  } catch (error) {
    handleFirestoreError(error, OperationType.CREATE, path);
  }
}
