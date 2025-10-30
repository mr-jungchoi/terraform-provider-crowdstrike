package cloudcompliance

import (
	"context"
	"fmt"
	"github.com/google/uuid"

	"github.com/crowdstrike/gofalcon/falcon/client/cloud_policies"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var controlAttrTypes = map[string]attr.Type{
	"id":          types.StringType,
	"name":        types.StringType,
	"description": types.StringType,
	"rules":       types.SetType{ElemType: types.StringType},
}

var sectionAttrTypes = map[string]attr.Type{
	"id":   types.StringType,
	"name": types.StringType,
	"controls": types.SetType{
		ElemType: types.ObjectType{
			AttrTypes: controlAttrTypes,
		},
	},
}

var crowdStrikeComplianceNamespace = uuid.MustParse("a1b2c3d4-e5f6-7890-abcd-ef1234567890")

// generateDeterministicUUID creates a consistent UUID based on framework and section names using UUID v5
func generateDeterministicUUID(frameworkName, sectionName string) string {
	// Create deterministic UUID v5 based on framework:section
	deterministicUUID := uuid.NewSHA1(crowdStrikeComplianceNamespace, []byte(fmt.Sprintf("%s:%s", frameworkName, sectionName)))
	return deterministicUUID.String()
}

// API parameter building utilities

func buildCreateFrameworkParams(
	ctx context.Context,
	plan cloudComplianceCustomFrameworkResourceModel,
) *cloud_policies.CreateComplianceFrameworkParams {
	name := plan.Name.ValueString()
	description := plan.Description.ValueString()

	createReq := &models.CommonCreateComplianceFrameworkRequest{
		Name:        &name,
		Description: &description,
		Active:      plan.Active.ValueBool(),
	}

	params := cloud_policies.NewCreateComplianceFrameworkParamsWithContext(ctx)
	params.SetBody(createReq)
	return params
}

func buildUpdateFrameworkParams(
	ctx context.Context,
	plan cloudComplianceCustomFrameworkResourceModel,
) *cloud_policies.UpdateComplianceFrameworkParams {
	name := plan.Name.ValueString()
	description := plan.Description.ValueString()

	updateReq := &models.CommonUpdateComplianceFrameworkRequest{
		Name:        &name,
		Description: &description,
		Active:      plan.Active.ValueBool(),
	}

	params := cloud_policies.NewUpdateComplianceFrameworkParamsWithContext(ctx)
	params.SetIds(plan.ID.ValueString())
	params.SetBody(updateReq)
	return params
}

func buildCreateControlParams(
	ctx context.Context,
	frameworkID, sectionName, controlName, description string,
) *cloud_policies.CreateComplianceControlParams {
	createReq := &models.CommonCreateComplianceControlRequest{
		Name:        &controlName,
		Description: &description,
		FrameworkID: &frameworkID,
		SectionName: &sectionName,
	}

	params := cloud_policies.NewCreateComplianceControlParamsWithContext(ctx)
	params.SetBody(createReq)
	return params
}

func buildRenameSectionParams(
	ctx context.Context,
	frameworkID, oldSectionName, newSectionName string,
) *cloud_policies.RenameSectionComplianceFrameworkParams {
	renameReq := &models.CommonRenameSectionRequest{
		SectionName: &newSectionName,
	}

	params := cloud_policies.NewRenameSectionComplianceFrameworkParamsWithContext(ctx)
	params.SetIds(frameworkID)
	params.SetSectionName(oldSectionName)
	params.SetBody(renameReq)
	return params
}

// Terraform type conversion utilities

func convertRulesToTerraformSet(rules []string) (types.Set, diag.Diagnostics) {
	var diags diag.Diagnostics

	ruleValues := make([]attr.Value, len(rules))
	for i, rule := range rules {
		ruleValues[i] = types.StringValue(rule)
	}

	rulesSet, setDiags := types.SetValue(types.StringType, ruleValues)
	diags.Append(setDiags...)

	return rulesSet, diags
}

func convertControlsMapToTerraformSet(ctx context.Context, controlsMap map[string]ControlModel) (types.Set, diag.Diagnostics) {
	var diags diag.Diagnostics

	controlsAttrValue := make([]attr.Value, 0, len(controlsMap))
	for _, control := range controlsMap {
		// Add name to the control model for the set representation
		controlWithName := ControlModel{
			ID:          control.ID,
			Name:        control.Name,
			Description: control.Description,
			Rules:       control.Rules,
		}

		controlValue, controlDiags := types.ObjectValueFrom(ctx, controlAttrTypes, controlWithName)
		diags.Append(controlDiags...)
		if diags.HasError() {
			continue
		}
		controlsAttrValue = append(controlsAttrValue, controlValue)
	}

	controlsSet, controlsSetDiags := types.SetValue(
		types.ObjectType{AttrTypes: controlAttrTypes},
		controlsAttrValue,
	)
	diags.Append(controlsSetDiags...)

	return controlsSet, diags
}

func convertSectionsMapToTerraformSet(ctx context.Context, sections map[string]SectionModel) (types.Set, diag.Diagnostics) {
	var diags diag.Diagnostics

	sectionsAttrValue := make([]attr.Value, 0, len(sections))
	for sectionName, section := range sections {
		// Add name to the section model for the set representation
		sectionWithName := SectionModel{
			ID:       section.ID,
			Name:     types.StringValue(sectionName),
			Controls: section.Controls,
		}

		sectionValue, sectionDiags := types.ObjectValueFrom(ctx, sectionAttrTypes, sectionWithName)
		diags.Append(sectionDiags...)
		if diags.HasError() {
			continue
		}
		sectionsAttrValue = append(sectionsAttrValue, sectionValue)
	}

	sectionsSet, sectionsSetDiags := types.SetValue(
		types.ObjectType{AttrTypes: sectionAttrTypes},
		sectionsAttrValue,
	)
	diags.Append(sectionsSetDiags...)

	return sectionsSet, diags
}

// Helper functions to convert sets back to maps for internal processing

func convertTerraformSetToControlsMap(ctx context.Context, controlsSet types.Set) (map[string]ControlModel, diag.Diagnostics) {
	var diags diag.Diagnostics
	controlsMap := make(map[string]ControlModel)

	if controlsSet.IsNull() || controlsSet.IsUnknown() {
		return controlsMap, diags
	}

	var controls []ControlModel
	diags.Append(controlsSet.ElementsAs(ctx, &controls, false)...)
	if diags.HasError() {
		return controlsMap, diags
	}

	for _, control := range controls {
		// Use control ID as the key, fallback to name if ID is not available
		key := control.ID.ValueString()
		if key == "" {
			key = control.Name.ValueString()
		}
		controlsMap[key] = control
	}

	return controlsMap, diags
}

func convertTerraformSetToSectionsMap(ctx context.Context, sectionsSet types.Set) (map[string]SectionModel, diag.Diagnostics) {
	var diags diag.Diagnostics
	sectionsMap := make(map[string]SectionModel)

	if sectionsSet.IsNull() || sectionsSet.IsUnknown() {
		return sectionsMap, diags
	}

	var sections []SectionModel
	diags.Append(sectionsSet.ElementsAs(ctx, &sections, false)...)
	if diags.HasError() {
		return sectionsMap, diags
	}

	for _, section := range sections {
		sectionsMap[section.Name.ValueString()] = section
	}

	return sectionsMap, diags
}
