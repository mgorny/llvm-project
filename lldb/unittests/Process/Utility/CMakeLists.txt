if (CMAKE_SYSTEM_NAME MATCHES "FreeBSD")
  add_lldb_unittest(RegisterContextFreeBSDTests
    RegisterContextFreeBSDTests.cpp

    LINK_LIBS
      lldbPluginProcessUtility
    )
endif()
