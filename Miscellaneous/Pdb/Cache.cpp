#include "Cache.hpp"

#include <ranges>

using namespace pdb;
using namespace msf;

#include "../../Configuration.hpp"

Cache::Cache(const Pdb &pdb):
	container {.records = typeRecords(pdb), .typeIndexRange = pdb.typeIndexRange()} {
	VM_SIZE_SPEED_BEGIN
	this->container.generateStructures();
	this->container.resolveForwardDeclarations();
	VM_SIZE_SPEED_END
}

const types::Structure *Cache::structure(const Hash hash) const noexcept {
	VM_SIZE_SPEED_BEGIN
	for (const auto &structure : this->container.structures | std::views::values)
		if (structure.name == hash)
			return &structure;
	VM_SIZE_SPEED_END
	return {};
}
const types::Structure *Cache::structure(const types::Variable *variable) const noexcept {
	VM_SIZE_SPEED_BEGIN
	if (variable->type != UnderlyingType::STRUCTURE)
		return {};

	auto typeIndex = variable->typeIndex;
	// Forwarded type index
	{
		const auto &forwardedStructures = this->container.forwardedStructures;
		if (const auto iterator = forwardedStructures.find(typeIndex);
			iterator != forwardedStructures.cend())
			return iterator->second.second;
	}

	if (this->container.isPointer(typeIndex))
		typeIndex = this->container.resolvePointerTypeIndex(typeIndex);
	for (const auto &[structureTypeIndex, structure] : this->container.structures)
		if (structureTypeIndex == typeIndex)
			return &structure;
	VM_SIZE_SPEED_END
	return {};
}

const types::Union *Cache::unions(const Hash hash) const noexcept {
	VM_SIZE_SPEED_BEGIN
	for (const auto &union_ : this->container.unions | std::views::values)
		if (union_.name == hash)
			return &union_;
	VM_SIZE_SPEED_END
	return {};
}
const types::Union *Cache::unions(const types::Variable *variable) const noexcept {
	VM_SIZE_SPEED_BEGIN
	if (variable->type != UnderlyingType::ENUM)
		return {};

	auto typeIndex = variable->typeIndex;
	// Forwarded type index
	{
		const auto &forwardedUnions = this->container.forwardedUnions;
		if (const auto iterator = forwardedUnions.find(typeIndex);
			iterator != forwardedUnions.cend())
			return iterator->second.second;
	}

	if (this->container.isPointer(typeIndex))
		typeIndex = this->container.resolvePointerTypeIndex(typeIndex);
	for (const auto &[unionTypeIndex, union_] : this->container.unions)
		if (unionTypeIndex == typeIndex)
			return &union_;
	VM_SIZE_SPEED_END
	return {};
}

const types::Enum *Cache::enums(const Hash hash) const noexcept {
	VM_SIZE_SPEED_BEGIN
	for (const auto &enum_ : this->container.enums | std::views::values)
		if (enum_.name == hash)
			return &enum_;
	VM_SIZE_SPEED_END
	return {};
}
const types::Enum *Cache::enums(const types::Variable *variable) const noexcept {
	VM_SIZE_SPEED_BEGIN
	if (variable->type != UnderlyingType::ENUM)
		return {};

	auto typeIndex = variable->typeIndex;
	// Forwarded type index
	{
		const auto &forwardedEnums = this->container.forwardedEnums;
		if (const auto iterator = forwardedEnums.find(typeIndex);
			iterator != forwardedEnums.cend())
			return iterator->second.second;
	}

	if (this->container.isPointer(typeIndex))
		typeIndex = this->container.resolvePointerTypeIndex(typeIndex);
	for (const auto &[enumTypeIndex, enum_] : this->container.enums)
		if (enumTypeIndex == typeIndex)
			return &enum_;
	VM_SIZE_SPEED_END
	return {};
}

const types::BitField *Cache::bitField(const types::Variable *variable) const noexcept {
	VM_SIZE_SPEED_BEGIN
	if (variable->type != UnderlyingType::BIT_FIELD)
		return {};

	auto typeIndex = variable->typeIndex;
	if (this->container.isPointer(typeIndex))
		typeIndex = this->container.resolvePointerTypeIndex(typeIndex);
	for (const auto &[bitFieldTypeIndex, bitField] : this->container.bitFields)
		if (bitFieldTypeIndex == typeIndex)
			return &bitField;
	VM_SIZE_SPEED_END
	return {};
}

const types::Array *Cache::array(const types::Variable *variable) const noexcept {
	VM_SIZE_SPEED_BEGIN
	if (variable->type != UnderlyingType::ARRAY)
		return {};

	auto typeIndex = variable->typeIndex;
	if (this->container.isPointer(typeIndex))
		typeIndex = this->container.resolvePointerTypeIndex(typeIndex);
	for (const auto &[arrayTypeIndex, array] : this->container.arrays)
		if (arrayTypeIndex == typeIndex)
			return &array;
	VM_SIZE_SPEED_END
	return {};
}
