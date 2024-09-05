
add_subdirectory(
	"src"
)

# Тестирование

if (MSVC)
if (W2E_UNIT_TESTING)
	add_subdirectory(
		"tests"
	)
endif (W2E_UNIT_TESTING)
endif (MSVC)
