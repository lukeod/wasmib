package wasmib

import (
	"errors"
	"fmt"

	"github.com/lukeod/wasmib/wasmib-go/proto"
	pb "google.golang.org/protobuf/proto"
)

// ErrUnsupportedVersion is returned when the schema version is not supported.
var ErrUnsupportedVersion = errors.New("unsupported schema version")

const (
	schemaVersion = 2
)

// Deserialize parses a protobuf-encoded SerializedModel.
func Deserialize(data []byte) (*Model, error) {
	// Unmarshal protobuf
	var msg proto.SerializedModel
	if err := pb.Unmarshal(data, &msg); err != nil {
		return nil, fmt.Errorf("unmarshaling protobuf: %w", err)
	}

	// Check version
	if msg.Version != schemaVersion {
		return nil, fmt.Errorf("%w: got %d, expected %d", ErrUnsupportedVersion, msg.Version, schemaVersion)
	}

	// Convert protobuf types to internal types
	modules := convertModules(msg.Modules)
	nodes := convertNodes(msg.Nodes)
	types := convertTypes(msg.Types)
	objects := convertObjects(msg.Objects)
	notifications := convertNotifications(msg.Notifications)

	// Convert unresolved details
	unresolvedImportDetails := convertUnresolvedImports(msg.UnresolvedImportDetails)
	unresolvedTypeDetails := convertUnresolvedTypes(msg.UnresolvedTypeDetails)
	unresolvedOidDetails := convertUnresolvedOids(msg.UnresolvedOidDetails)
	unresolvedIndexDetails := convertUnresolvedIndexes(msg.UnresolvedIndexDetails)
	unresolvedNotifDetails := convertUnresolvedNotifs(msg.UnresolvedNotifDetails)

	m := &Model{
		version:                       msg.Version,
		modules:                       modules,
		nodes:                         nodes,
		types:                         types,
		objects:                       objects,
		notifications:                 notifications,
		roots:                         msg.Roots,
		unresolvedImports:             msg.UnresolvedImports,
		unresolvedTypes:               msg.UnresolvedTypes,
		unresolvedOids:                msg.UnresolvedOids,
		unresolvedIndexes:             msg.UnresolvedIndexes,
		unresolvedNotificationObjects: msg.UnresolvedNotificationObjects,
		unresolvedImportDetails:       unresolvedImportDetails,
		unresolvedTypeDetails:         unresolvedTypeDetails,
		unresolvedOidDetails:          unresolvedOidDetails,
		unresolvedIndexDetails:        unresolvedIndexDetails,
		unresolvedNotifDetails:        unresolvedNotifDetails,
	}

	m.buildIndices()
	return m, nil
}

func convertModules(pbModules []*proto.SerializedModule) []Module {
	modules := make([]Module, len(pbModules))
	for i, pb := range pbModules {
		modules[i] = Module{
			Name:         pb.Name,
			LastUpdated:  pb.LastUpdated,
			ContactInfo:  pb.ContactInfo,
			Organization: pb.Organization,
			Description:  pb.Description,
			Revisions:    convertRevisions(pb.Revisions),
		}
	}
	return modules
}

func convertRevisions(pbRevisions []*proto.SerializedRevision) []Revision {
	revisions := make([]Revision, len(pbRevisions))
	for i, pb := range pbRevisions {
		revisions[i] = Revision{
			Date:        pb.Date,
			Description: pb.Description,
		}
	}
	return revisions
}

func convertNodes(pbNodes []*proto.SerializedNode) []Node {
	nodes := make([]Node, len(pbNodes))
	for i, pb := range pbNodes {
		nodes[i] = Node{
			ID:          uint32(i + 1), // 1-indexed
			Subid:       pb.Subid,
			Parent:      pb.Parent,
			Children:    pb.Children,
			Kind:        NodeKind(pb.Kind),
			Definitions: convertNodeDefs(pb.Definitions),
		}
	}
	return nodes
}

func convertNodeDefs(pbDefs []*proto.SerializedNodeDef) []NodeDef {
	defs := make([]NodeDef, len(pbDefs))
	for i, pb := range pbDefs {
		defs[i] = NodeDef{
			Module:       pb.Module,
			Label:        pb.Label,
			Object:       pb.Object,
			Notification: pb.Notification,
		}
	}
	return defs
}

func convertTypes(pbTypes []*proto.SerializedType) []Type {
	types := make([]Type, len(pbTypes))
	for i, pb := range pbTypes {
		types[i] = Type{
			Module:      pb.Module,
			Name:        pb.Name,
			Base:        BaseType(pb.Base),
			Parent:      pb.Parent,
			Status:      Status(pb.Status),
			IsTC:        pb.IsTc,
			Hint:        pb.Hint,
			Description: pb.Description,
			Size:        convertConstraint(pb.Size),
			Range:       convertConstraint(pb.Range),
			EnumValues:  convertEnumValues(pb.EnumValues),
			BitDefs:     convertBitDefs(pb.BitDefs),
		}
	}
	return types
}

func convertConstraint(pb *proto.SerializedConstraint) *Constraint {
	if pb == nil || len(pb.Ranges) == 0 {
		return nil
	}
	ranges := make([][2]int64, len(pb.Ranges))
	for i, r := range pb.Ranges {
		ranges[i] = [2]int64{r.Min, r.Max}
	}
	return &Constraint{Ranges: ranges}
}

func convertEnumValues(pbValues []*proto.EnumValue) []EnumValue {
	if len(pbValues) == 0 {
		return nil
	}
	values := make([]EnumValue, len(pbValues))
	for i, pb := range pbValues {
		values[i] = EnumValue{
			Value: pb.Value,
			Name:  pb.Name,
		}
	}
	return values
}

func convertBitDefs(pbDefs []*proto.BitDef) []BitDef {
	if len(pbDefs) == 0 {
		return nil
	}
	defs := make([]BitDef, len(pbDefs))
	for i, pb := range pbDefs {
		defs[i] = BitDef{
			Position: pb.Position,
			Name:     pb.Name,
		}
	}
	return defs
}

func convertObjects(pbObjects []*proto.SerializedObject) []Object {
	objects := make([]Object, len(pbObjects))
	for i, pb := range pbObjects {
		objects[i] = Object{
			Node:        pb.Node,
			Module:      pb.Module,
			Name:        pb.Name,
			TypeID:      pb.TypeId,
			Access:      Access(pb.Access),
			Status:      Status(pb.Status),
			Description: pb.Description,
			Units:       pb.Units,
			Reference:   pb.Reference,
			Index:       convertIndex(pb.Index),
			Augments:    pb.Augments,
			DefVal:      convertDefVal(pb.Defval),
			InlineEnum:  convertEnumValues(pb.InlineEnum),
			InlineBits:  convertBitDefs(pb.InlineBits),
		}
	}
	return objects
}

func convertIndex(pb *proto.SerializedIndex) *IndexSpec {
	if pb == nil || len(pb.Items) == 0 {
		return nil
	}
	items := make([]IndexItem, len(pb.Items))
	for i, item := range pb.Items {
		items[i] = IndexItem{
			Object:  item.Object,
			Implied: item.Implied,
		}
	}
	return &IndexSpec{Items: items}
}

func convertDefVal(pb *proto.SerializedDefVal) *DefVal {
	if pb == nil {
		return nil
	}
	// Check if any field is actually set (kind alone isn't enough for proto3)
	// We rely on the presence of kind > 0 or any other field being non-zero
	hasValue := pb.IntVal != nil || pb.UintVal != nil || pb.StrVal != nil ||
		pb.RawStr != nil || pb.NodeVal != nil || len(pb.BitsVal) > 0

	if pb.Kind == 0 && !hasValue {
		return nil
	}

	d := &DefVal{Kind: DefValKind(pb.Kind)}
	if pb.IntVal != nil {
		d.IntVal = *pb.IntVal
	}
	if pb.UintVal != nil {
		d.UintVal = *pb.UintVal
	}
	if pb.StrVal != nil {
		d.StrVal = *pb.StrVal
	}
	if pb.RawStr != nil {
		d.RawStr = *pb.RawStr
	}
	if pb.NodeVal != nil {
		d.NodeID = *pb.NodeVal
	}
	if len(pb.BitsVal) > 0 {
		d.BitsVals = pb.BitsVal
	}
	return d
}

func convertNotifications(pbNotifs []*proto.SerializedNotification) []Notification {
	notifications := make([]Notification, len(pbNotifs))
	for i, pb := range pbNotifs {
		notifications[i] = Notification{
			Node:        pb.Node,
			Module:      pb.Module,
			Name:        pb.Name,
			Status:      Status(pb.Status),
			Description: pb.Description,
			Reference:   pb.Reference,
			Objects:     pb.Objects,
		}
	}
	return notifications
}

func convertUnresolvedImports(pbImports []*proto.UnresolvedImport) []UnresolvedImport {
	imports := make([]UnresolvedImport, len(pbImports))
	for i, pb := range pbImports {
		imports[i] = UnresolvedImport{
			ImportingModule: pb.ImportingModule,
			FromModule:      pb.FromModule,
			Symbol:          pb.Symbol,
			Reason:          UnresolvedImportReason(pb.Reason),
		}
	}
	return imports
}

func convertUnresolvedTypes(pbTypes []*proto.UnresolvedType) []UnresolvedType {
	types := make([]UnresolvedType, len(pbTypes))
	for i, pb := range pbTypes {
		types[i] = UnresolvedType{
			Module:     pb.Module,
			Referrer:   pb.Referrer,
			Referenced: pb.Referenced,
		}
	}
	return types
}

func convertUnresolvedOids(pbOids []*proto.UnresolvedOid) []UnresolvedOid {
	oids := make([]UnresolvedOid, len(pbOids))
	for i, pb := range pbOids {
		oids[i] = UnresolvedOid{
			Module:     pb.Module,
			Definition: pb.Definition,
			Component:  pb.Component,
		}
	}
	return oids
}

func convertUnresolvedIndexes(pbIndexes []*proto.UnresolvedIndex) []UnresolvedIndex {
	indexes := make([]UnresolvedIndex, len(pbIndexes))
	for i, pb := range pbIndexes {
		indexes[i] = UnresolvedIndex{
			Module:      pb.Module,
			Row:         pb.Row,
			IndexObject: pb.IndexObject,
		}
	}
	return indexes
}

func convertUnresolvedNotifs(pbNotifs []*proto.UnresolvedNotificationObject) []UnresolvedNotificationObject {
	notifs := make([]UnresolvedNotificationObject, len(pbNotifs))
	for i, pb := range pbNotifs {
		notifs[i] = UnresolvedNotificationObject{
			Module:       pb.Module,
			Notification: pb.Notification,
			Object:       pb.Object,
		}
	}
	return notifs
}
