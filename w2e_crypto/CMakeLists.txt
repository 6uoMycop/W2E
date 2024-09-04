
add_subdirectory(
	"src"
)

# Тестирование

if (MSVC)
if (UNIT_TESTING)
	add_subdirectory(
		"tests"
	)
endif (UNIT_TESTING)
endif (MSVC)
