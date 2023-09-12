#include "Container.hpp"

#include "msf/Type Index.hpp"
#include "msf/Leaf Type.hpp"
#include "Data Stream/Reader.hpp"

#include <Framework/Utilities/Strings/Fnv1A.hpp>
using Hash = Framework::Utilities::Strings::Fnv1A::Hash;
#include <Framework/Utilities/Strings/XorStr.hpp>

#include <ranges>
#include <iterator>

using namespace pdb;
using namespace msf;

#include "../Globals.hpp"

#include <intrin.h>
template<class ...Arguments>
void print(const char *format, Arguments &&...arguments) {
	if constexpr (Configuration::print) {
		VM_SIZE_BEGIN
		using namespace KM::Miscellaneous::Globals;
		NT::DbgPrintEx(DPFLTR_SYSTEM_ID, DPFLTR_ERROR_LEVEL, (std::string {format} + '\n').c_str(), std::forward<Arguments>(arguments)...);
		VM_SIZE_END
		__nop(); // Prevent tailcall optimizations
	}
}

void Container::generateStructures() {
	VM_SIZE_SPEED_BEGIN
	for (std::size_t i {0x1000}, j {}; j < this->records.size(); ++i, ++j) {
		if (this->isClassType(i)) {
			this->parseClass(i, this->records[j]);
			continue;
		}
		if (this->isUnionType(i)) {
			this->parseUnion(i, this->records[j]);
			continue;
		}
		if (this->isEnumType(i)) {
			this->parseEnum(i, this->records[j]);
			continue;
		}
		if (this->isBitFieldType(i)) {
			this->parseBitField(i, this->records[j]);
			continue;
		}
		if (this->isArrayType(i)) {
			this->parseArray(i, this->records[j]);
			continue;
		}
	}
	VM_SIZE_SPEED_END
}
void Container::resolveForwardDeclarations() {
	VM_SIZE_SPEED_BEGIN
	// Structures
	for (auto &[forwardedName, forwardedPointer] : this->forwardedStructures | std::views::values)
		for (const auto &structure : this->structures | std::views::values)
			if (structure.name == forwardedName)
				forwardedPointer = &structure;

	// Unions
	for (auto &[forwardedName, forwardedPointer] : this->forwardedUnions | std::views::values)
		for (const auto &union_ : this->unions | std::views::values)
			if (union_.name == forwardedName)
				forwardedPointer = &union_;

	// Enums
	for (auto &[forwardedName, forwardedPointer] : this->forwardedEnums | std::views::values)
		for (const auto &enum_ : this->enums | std::views::values)
			if (enum_.name == forwardedName)
				forwardedPointer = &enum_;
	VM_SIZE_SPEED_END
}

bool Container::isPointer(const std::size_t typeIndex) const noexcept {
	VM_SIZE_SPEED_BEGIN
	const auto [typeIndexBegin, typeIndexEnd] = this->typeIndexRange;
	if (typeIndex < typeIndexBegin)
		return static_cast<SimpleTypeMode>(typeIndex & 0xFF00) != SimpleTypeMode::DIRECT;

	const auto record = this->records[typeIndex - typeIndexBegin];
	volatile const auto result = static_cast<LeafType>(record->kind) == LeafType::POINTER;
	VM_SIZE_SPEED_END
	return result;
}
UInt32 Container::resolvePointerTypeIndex(const std::size_t typeIndex) const noexcept {
	VM_SIZE_SPEED_BEGIN
	const auto [typeIndexBegin, typeIndexEnd] = this->typeIndexRange;
	if (typeIndex < typeIndexBegin)
		return {};
	volatile const auto result = resolvePointerTypeIndex(this->records[typeIndex - typeIndexBegin]);
	VM_SIZE_SPEED_END
	return result;
}

bool Container::isClassType(const std::size_t typeIndex) const noexcept {
	VM_SIZE_SPEED_BEGIN
	const auto [typeIndexBegin, typeIndexEnd] = this->typeIndexRange;
	if (typeIndex < typeIndexBegin)
		return false;

	const auto leafType = static_cast<LeafType>(this->records[typeIndex - typeIndexBegin]->kind);
	volatile const auto result = leafType == LeafType::CLASS || leafType == LeafType::STRUCTURE || leafType == LeafType::INTERFACE;
	VM_SIZE_SPEED_END
	return result;
}
bool Container::isUnionType(const std::size_t typeIndex) const noexcept {
	VM_SIZE_SPEED_BEGIN
	const auto [typeIndexBegin, typeIndexEnd] = this->typeIndexRange;
	if (typeIndex < typeIndexBegin)
		return false;

	const auto leafType = static_cast<LeafType>(this->records[typeIndex - typeIndexBegin]->kind);
	volatile const auto result =  leafType == LeafType::UNION;
	VM_SIZE_SPEED_END
	return result;
}
bool Container::isEnumType(const std::size_t typeIndex) const noexcept {
	VM_SIZE_SPEED_BEGIN
	const auto [typeIndexBegin, typeIndexEnd] = this->typeIndexRange;
	if (typeIndex < typeIndexBegin)
		return false;

	const auto leafType = static_cast<LeafType>(this->records[typeIndex - typeIndexBegin]->kind);
	volatile const auto result = leafType == LeafType::ENUM;
	VM_SIZE_SPEED_END
	return result;
}
bool Container::isBitFieldType(const std::size_t typeIndex) const noexcept {
	VM_SIZE_SPEED_BEGIN
	const auto [typeIndexBegin, typeIndexEnd] = this->typeIndexRange;
	if (typeIndex < typeIndexBegin)
		return false;

	const auto leafType = static_cast<LeafType>(this->records[typeIndex - typeIndexBegin]->kind);
	volatile const auto result = leafType == LeafType::BIT_FIELD;
	VM_SIZE_SPEED_END
	return result;
}
bool Container::isArrayType(const std::size_t typeIndex) const noexcept {
	VM_SIZE_SPEED_BEGIN
	const auto [typeIndexBegin, typeIndexEnd] = this->typeIndexRange;
	if (typeIndex < typeIndexBegin)
		return false;

	const auto leafType = static_cast<LeafType>(this->records[typeIndex - typeIndexBegin]->kind);
	volatile const auto result = leafType == LeafType::ARRAY;
	VM_SIZE_SPEED_END
	return result;
}

UInt32 Container::resolvePointerTypeIndex(const codeview::Record *record) noexcept {
	VM_SIZE_SPEED_BEGIN
	stream::Reader pointerReader {
		reinterpret_cast<const UInt8*>(record) + sizeof(record->length) + sizeof(record->kind),
		record->length - sizeof(record->kind)};
	volatile const auto result = pointerReader.read<UInt32>();
	VM_SIZE_SPEED_END
	return result;
}
UnderlyingType Container::underlyingType(const std::size_t typeIndex) const noexcept {
	VM_SIZE_SPEED_BEGIN
	const auto [typeIndexBegin, typeIndexEnd] = this->typeIndexRange;
	if (typeIndex < typeIndexBegin) {
		// Parse simple (constructed) types (e.g. unsigned long)
		const auto baseType = static_cast<SimpleType>(typeIndex & 0xFF);
		if (baseType == SimpleType::VOID_) return UnderlyingType::VOID_;
		if (baseType == SimpleType::HRESULT) return UnderlyingType::LONG32;
		if (baseType == SimpleType::SIGNED_CHARACTER || baseType == SimpleType::NARROW_CHARACTER) return UnderlyingType::CHAR;
		if (baseType == SimpleType::UNSIGNED_CHARACTER) return UnderlyingType::UCHAR;
		if (baseType == SimpleType::WIDE_CHARACTER) return UnderlyingType::WCHAR;
		if (baseType == SimpleType::CHARACTER16) return UnderlyingType::CHAR16;
		if (baseType == SimpleType::CHARACTER32) return UnderlyingType::CHAR32;
		if (baseType == SimpleType::SBYTE) return UnderlyingType::INT8;
		if (baseType == SimpleType::BYTE) return UnderlyingType::UINT8;
		if (baseType == SimpleType::INT16 || baseType == SimpleType::INT16_SHORT) return UnderlyingType::INT16;
		if (baseType == SimpleType::UINT16 || baseType == SimpleType::UINT16_SHORT) return UnderlyingType::UINT16;
		if (baseType == SimpleType::INT32) return UnderlyingType::INT32;
		if (baseType == SimpleType::UINT32) return UnderlyingType::UINT32;
		if (baseType == SimpleType::INT32_LONG) return UnderlyingType::LONG32;
		if (baseType == SimpleType::UINT32_LONG) return UnderlyingType::ULONG32;
		if (baseType == SimpleType::INT64_QUAD) return UnderlyingType::LONG64;
		if (baseType == SimpleType::UINT64_QUAD) return UnderlyingType::ULONG64;
		if (baseType == SimpleType::INT64) return UnderlyingType::INT64;
		if (baseType == SimpleType::UINT64) return UnderlyingType::UINT64;
		if (baseType == SimpleType::INT128 || baseType == SimpleType::INT128_OCT) return UnderlyingType::INT128;
		if (baseType == SimpleType::UINT128 || baseType == SimpleType::UINT128_OCT) return UnderlyingType::UINT128;
		if (baseType == SimpleType::FLOAT32) return UnderlyingType::FLOAT;
		if (baseType == SimpleType::COMPLEX64) return UnderlyingType::DOUBLE;
		if (baseType == SimpleType::BOOLEAN8) return UnderlyingType::BOOL;
		return UnderlyingType::NONE;
	}

	const auto record = this->records[typeIndex - typeIndexBegin];
	const auto leafType = static_cast<LeafType>(record->kind);
	if (leafType == LeafType::CLASS || leafType == LeafType::STRUCTURE || leafType == LeafType::INTERFACE) return UnderlyingType::STRUCTURE;
	if (leafType == LeafType::UNION) return UnderlyingType::UNION;
	if (leafType == LeafType::ENUM) return UnderlyingType::ENUM;
	if (leafType == LeafType::ARRAY) return UnderlyingType::ARRAY;
	if (leafType == LeafType::BIT_FIELD) return UnderlyingType::BIT_FIELD;
	if (leafType == LeafType::PROCEDURE) return UnderlyingType::PROCEDURE;
	if (leafType == LeafType::POINTER)
		return this->underlyingType(this->resolvePointerTypeIndex(record));

	volatile auto result = UnderlyingType::NONE;
	VM_SIZE_SPEED_END
	return result;
}

std::vector<Container::TypeVariant> Container::parseFieldList(const std::size_t typeIndex, const std::size_t expectedNumberOfFields) const {
	VM_SIZE_SPEED_BEGIN
	const auto [typeIndexBegin, typeIndexEnd] = this->typeIndexRange;
	if (typeIndex < typeIndexBegin)
		return {};

	const auto fieldListRecord = this->records[typeIndex - typeIndexBegin];
	if (static_cast<LeafType>(fieldListRecord->kind) != LeafType::FIELD_LIST)
		return {};

	std::vector<TypeVariant> parsedFieldList {};
	parsedFieldList.reserve(expectedNumberOfFields);

	stream::Reader fieldListReader {
		reinterpret_cast<const UInt8*>(fieldListRecord) + sizeof(fieldListRecord->length) + sizeof(fieldListRecord->kind),
		fieldListRecord->length - sizeof(fieldListRecord->kind)};
	while (!fieldListReader.empty()) {
		const auto type = fieldListReader.read<LeafType>();
		if (type == LeafType::MEMBER) {
			const auto attributes = *fieldListReader.read<const FieldAttributes*>();
			const auto fieldTypeIndex = fieldListReader.read<UInt32>();
			const auto fieldOffset = static_cast<std::size_t>(fieldListReader.read<stream::SignAwareInteger>());
			const Hash name {fieldListReader.read<std::string_view>()};

			// Skip any potential padding
			fieldListReader.skipPadding();

			// Insert the variable
			parsedFieldList.emplace_back(types::Variable {name, fieldOffset, attributes, this->underlyingType(fieldTypeIndex), fieldTypeIndex});
		} else if (type == LeafType::ENUMERATE) {
			fieldListReader.skip(sizeof(FieldAttributes));
			//const auto attributes = *fieldListReader.read<const FieldAttributes*>();
			const auto value = static_cast<std::size_t>(fieldListReader.read<stream::SignAwareInteger>());
			const Hash name {fieldListReader.read<std::string_view>()};

			// Skip any potential padding
			fieldListReader.skipPadding();

			// Insert the value
			parsedFieldList.emplace_back(types::Enumerator {.name = name, .value = {.uint64 = value}});
		} else {
			if constexpr (Configuration::print)
				print(xorstr_("Unexpected leaf type when parsing a field list."));
			__debugbreak(); // Not implemented
		}
	}
	VM_SIZE_SPEED_END
	return parsedFieldList;
}
std::vector<types::Variable> Container::parseVariables(const std::size_t typeIndex, const std::size_t expectedNumberOfFields) const {
	VM_SIZE_SPEED_BEGIN
	const auto fieldList = this->parseFieldList(typeIndex, expectedNumberOfFields);

	constexpr auto isVariable = [](const auto &variant) { return std::holds_alternative<types::Variable>(variant); };
	constexpr auto transform = [](const auto &variant) -> const types::Variable& { return std::get<types::Variable>(variant); };

	std::vector<types::Variable> variables {};
	std::ranges::copy(fieldList | std::views::filter(isVariable) | std::views::transform(transform), std::back_inserter(variables));
	VM_SIZE_SPEED_END
	return variables;
}
std::vector<types::Enumerator> Container::parseEnumerators(const std::size_t typeIndex, const std::size_t expectedNumberOfFields) const {
	VM_SIZE_SPEED_BEGIN
	const auto fieldList = this->parseFieldList(typeIndex, expectedNumberOfFields);

	constexpr auto isEnumerator = [](const auto &variant) { return std::holds_alternative<types::Enumerator>(variant); };
	constexpr auto transform = [](const auto &variant) -> const types::Enumerator& { return std::get<types::Enumerator>(variant); };

	std::vector<types::Enumerator> values {};
	std::ranges::copy(fieldList | std::views::filter(isEnumerator) | std::views::transform(transform), std::back_inserter(values));
	VM_SIZE_SPEED_END
	return values;
}

void Container::parseClass(const std::size_t typeIndex, const codeview::Record *record) {
	VM_SIZE_SPEED_BEGIN
	stream::Reader classReader {reinterpret_cast<const stream::UnderlyingDataType*>(record) + sizeof(*record), record->length - sizeof(record->length)};

	const auto numberOfFields = classReader.read<UInt16>();
	const auto properties = *classReader.read<const types::Properties*>();
	const auto fieldListTypeIndex = classReader.read<UInt32>();
	classReader.skip(sizeof(UInt32) * 2);
	//[[maybe_unused]] const auto derivedTypeIndex = classReader.read<UInt32>();
	//[[maybe_unused]] const auto virtualShapeTableTypeIndex = classReader.read<UInt32>();

	const auto sizeOf = static_cast<std::size_t>(classReader.read<stream::SignAwareInteger>());
	const Hash name {classReader.read<std::string_view>()};
	if (properties.uniqueName())
		static_cast<void>(classReader.read<std::string_view>());

	// Skip any potential padding
	classReader.skipPadding();
	if (!classReader.empty()) // At this point the reader should be empty!
		return;

	// Check if the record is forward declared
	if (properties.forwardReference())
		this->forwardedStructures.try_emplace(typeIndex, name, nullptr);
	else
		// Parse the field list and insert the structure
		this->structures.try_emplace(typeIndex, name, sizeOf, this->parseVariables(fieldListTypeIndex, numberOfFields));
	VM_SIZE_SPEED_END
}
void Container::parseUnion(const std::size_t typeIndex, const codeview::Record *record) {
	VM_SIZE_SPEED_BEGIN
	stream::Reader unionReader {reinterpret_cast<const stream::UnderlyingDataType*>(record) + sizeof(*record), record->length - sizeof(record->length)};

	const auto numberOfFields = unionReader.read<UInt16>();
	const auto properties = *unionReader.read<const types::Properties*>();
	const auto fieldListTypeIndex = unionReader.read<UInt32>();
	const auto sizeOf = static_cast<std::size_t>(unionReader.read<stream::SignAwareInteger>());
	const Hash name {unionReader.read<std::string_view>()};
	if (properties.uniqueName())
		static_cast<void>(unionReader.read<std::string_view>());

	// Skip any potential padding
	unionReader.skipPadding();
	if (!unionReader.empty()) // At this point the reader should be empty!
		return;

	// Check if the record is forward declared
	if (properties.forwardReference())
		this->forwardedUnions.try_emplace(typeIndex, name, nullptr);
	else
		// Parse the field list and insert the structure
		this->unions.try_emplace(typeIndex, name, sizeOf, this->parseVariables(fieldListTypeIndex, numberOfFields));
	VM_SIZE_SPEED_END
}
void Container::parseEnum(const std::size_t typeIndex, const codeview::Record *record) {
	VM_SIZE_SPEED_BEGIN
	stream::Reader enumReader {reinterpret_cast<const stream::UnderlyingDataType*>(record) + sizeof(*record), record->length - sizeof(record->length)};

	const auto numberOfEnumerators = enumReader.read<UInt16>();
	const auto properties = *enumReader.read<const types::Properties*>();
	const auto underlyingType = this->underlyingType(enumReader.read<UInt32>());
	const auto fieldListTypeIndex = enumReader.read<UInt32>();
	const Hash name {enumReader.read<std::string_view>()};
	if (properties.uniqueName())
		static_cast<void>(enumReader.read<std::string_view>());

	// Skip any potential padding
	enumReader.skipPadding();
	if (!enumReader.empty()) // At this point the reader should be empty!
		return;

	// Check if the record is forward declared
	if (properties.forwardReference())
		this->forwardedEnums.try_emplace(typeIndex, name, nullptr);
	else
		// Parse the field list and insert the structure
		this->enums.try_emplace(typeIndex, name, underlyingType, this->parseEnumerators(fieldListTypeIndex, numberOfEnumerators));
	VM_SIZE_SPEED_END
}
void Container::parseBitField(const std::size_t typeIndex, const codeview::Record *record) {
	VM_SIZE_SPEED_BEGIN
	stream::Reader bitFieldReader {reinterpret_cast<const stream::UnderlyingDataType*>(record) + sizeof(*record), record->length - sizeof(record->length)};

	const auto underlyingTypeIndex = bitFieldReader.read<UInt32>();
	const auto bitSize = bitFieldReader.read<UInt8>();
	const auto bitOffset = bitFieldReader.read<UInt8>();

	// Skip any potential padding
	bitFieldReader.skipPadding();
	if (!bitFieldReader.empty()) // At this point the reader should be empty!
		return;

	this->bitFields.try_emplace(typeIndex, this->underlyingType(underlyingTypeIndex), underlyingTypeIndex, bitSize, bitOffset);
	VM_SIZE_SPEED_END
}
void Container::parseArray(const std::size_t typeIndex, const codeview::Record *record) {
	VM_SIZE_SPEED_BEGIN
	stream::Reader arrayReader {reinterpret_cast<const stream::UnderlyingDataType*>(record) + sizeof(*record), record->length - sizeof(record->length)};

	const auto elementTypeIndex = arrayReader.read<UInt32>();
	const auto indexTypeIndex = arrayReader.read<UInt32>();
	const auto numberOfElements = static_cast<std::size_t>(arrayReader.read<stream::SignAwareInteger>());
	static_cast<void>(arrayReader.read<std::string_view>());

	// Skip any potential padding
	arrayReader.skipPadding();
	if (!arrayReader.empty()) // At this point the reader should be empty!
		return;

	this->arrays.try_emplace(typeIndex, elementTypeIndex, indexTypeIndex, numberOfElements);
	VM_SIZE_SPEED_END
}
