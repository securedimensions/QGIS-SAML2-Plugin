cmake_minimum_required(VERSION 2.8.12)

if(POLICY CMP0048) # in CMake >= 3.0.0
    cmake_policy(SET CMP0048 OLD) # keep project() from clearing VERSION variables
endif(POLICY CMP0048)
set(VER_MAJOR "0")
set(VER_MINOR "1")
set(VER_PATCH "0")
set(API_VER_PATCH "0")
set(CPACK_PACKAGE_VERSION_MAJOR ${VER_MAJOR})
set(CPACK_PACKAGE_VERSION_MINOR ${VER_MINOR})
set(CPACK_PACKAGE_VERSION_PATCH ${VER_PATCH})
set(PROJECT_VERSION ${VER_MAJOR}.${VER_MINOR}.${VER_PATCH})
set(API_VERSION ${VER_MAJOR}.${VER_MINOR}.${API_VER_PATCH})

project(qgis-saml2-method-plugin)

if(CMAKE_BUILD_TYPE MATCHES Debug OR CMAKE_BUILD_TYPE MATCHES RelWithDebInfo)
  message (STATUS "Debug output enabled")
  add_definitions(-UQT_NO_DEBUG_OUTPUT)
  add_definitions(-DQGISDEBUG=1)
endif()

option(USE_CXX_11 "Enable C++11 compiler support" ON)

#allow override keyword if available
if(USE_CXX_11)
  set(CMAKE_CXX_STANDARD 11)
else()
  add_definitions("-Doverride=")
  add_definitions("-Dnullptr=0")
endif()

if(APPLE)
  add_definitions(-DQT_NO_CAST_TO_ASCII)
endif(APPLE)

########################################################
# Packages
SET(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake ${CMAKE_MODULE_PATH})

# Find QGIS
# help find custom locations
if(APPLE)
  set(QGIS_PREFIX_PATH "/Applications" CACHE STRING "macOS QGIS application install prefix")

  #this will define ${APP_SERVICES_LIBRARY}
  find_library(APP_SERVICES_LIBRARY ApplicationServices )
  if(EXISTS "${QGIS_PREFIX_PATH}/CMakeCache.txt")
    set(QGIS_BUILD_PATH "${QGIS_PREFIX_PATH}")
    add_definitions("-DQGIS_BUILD_PATH=\"${QGIS_BUILD_PATH}\"")
  elseif(EXISTS "${QGIS_PREFIX_PATH}/QGIS.app")
    set(QGIS_MAC_PATH "${QGIS_PREFIX_PATH}/QGIS.app/Contents")
  endif()
  if (USE_CXX_11)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-error=c++11-narrowing -Wno-return-type-c-linkage")
  endif ()
elseif(MSVC)
  # or C:/PROGRA~1/Boundless/Desktop/osgeo4w
  set(OSGEO4W_ROOT_DIR "C:/OSGeo4W64" CACHE STRING "OSGeo4W root install prefix")
  set(ENV{OSGEO4W_ROOT} $OSGEO4W_ROOT_DIR)
endif()

find_package(QGIS REQUIRED)

if(NOT QGIS_PLUGIN_DIR)
  message(WARNING "Couldn't find QGIS_PLUGIN_DIR; install may fail")
endif()

if("${QGIS_VERSION}" VERSION_LESS "2.99.0")
  set(QGIS2 TRUE)
  message(STATUS "QGIS target version set to 2.x")
else()
  set(QGIS2 FALSE)
  message(STATUS "QGIS target version set to 3.x")
endif()


# Qt find routines from QGIS 2.14.3 code base
set(QT_MIN_VERSION 4.8.0)

option(WITH_QTWEBKIT "Enable QtWebkit support" ON)
if(WITH_QTWEBKIT)
  add_definitions(-DWITH_QTWEBKIT)
endif()

if(NOT QGIS2)
  find_package(Qt5Core QUIET)
  find_package(Qt5Gui REQUIRED)
  find_package(Qt5Widgets REQUIRED)
  find_package(Qt5Network REQUIRED)
  find_package(Qt5Svg REQUIRED)
  find_package(Qt5Xml REQUIRED)
  find_package(Qt5Concurrent REQUIRED)
  find_package(Qt5PrintSupport REQUIRED)
  find_package(Qt5Positioning)
  if (WITH_QTWEBKIT)
    find_package(Qt5WebKit REQUIRED)
    find_package(Qt5WebKitWidgets REQUIRED)
  endif()
  find_package(Qt5Test REQUIRED)
  find_package(Qt5UiTools REQUIRED)
  find_package(Qt5Script REQUIRED)
  find_package(Qt5Sql REQUIRED)
  include("cmake/modules/ECMQt4To5Porting.cmake")
  message(STATUS "Found Qt version: ${Qt5Core_VERSION_STRING}")
else()
  find_package(Qt4 ${QT_MIN_VERSION} REQUIRED)
  set(QT_USE_QTXML 1)
  set(QT_USE_QTNETWORK 1)
  set(QT_USE_QTSVG 1)
  set(QT_USE_QTSQL 1)
  set(QT_USE_QTWEBKIT 1)
  if(NOT QT_QTXML_FOUND OR NOT QT_QTNETWORK_FOUND OR NOT QT_QTSVG_FOUND OR
      NOT QT_QTSQL_FOUND OR NOT QT_QTWEBKIT_FOUND OR
      (WITH_CUSTOM_WIDGETS AND NOT QT_QTDESIGNER_FOUND))
    message(SEND_ERROR "Some Qt4 modules haven't been found!")
  endif()

  include(${QT_USE_FILE})
  message(STATUS "Found Qt version: ${QTVERSION}")

endif()

find_package(QCA REQUIRED)

#if(QGIS2)
  # export headers (e.g. qgis_core.h) are now used in QGIS 2.99+
  if(WIN32)
    set(DLLIMPORT "__declspec(dllimport)")
    set(DLLEXPORT "__declspec(dllexport)")
  else (WIN32)
    if("${CMAKE_CXX_COMPILER_ID}" MATCHES "GNU" OR "${CMAKE_CXX_COMPILER_ID}" MATCHES "Clang")
      set(DLLEXPORT "__attribute__ ((visibility (\\\"default\\\")))")
    else()
      set(DLLEXPORT "")
    endif()
  endif(WIN32)
  add_definitions("-DCORE_EXPORT=${DLLIMPORT}")
  add_definitions("-DGUI_EXPORT=${DLLIMPORT}")
  add_definitions("-DAPP_EXPORT=${DLLIMPORT}")
#endif()

IF(QGIS_APP_NAME)
  #message(STATUS "Building OAuth2 plugin in QGIS src tree")
  # we are in QGIS src tree
  SET(IN_QGIS_SRC TRUE)
  #use its version
  SET(QGIS_VERSION "${COMPLETE_VERSION}")
ENDIF()

IF(NOT QGIS_VERSION)
  MESSAGE(FATAL_ERROR "QGIS_VERSION undetermined")
ENDIF()

IF("${QGIS_VERSION}" VERSION_LESS "2.99.0")
  SET(QGIS2 TRUE)
  MESSAGE(STATUS "QGIS target version for SAML2 plugin set to 2.x")
ELSE()
  SET(QGIS2 FALSE)
  MESSAGE(STATUS "QGIS target version for SAML2 plugin set to 3.x")
ENDIF()

IF(NOT QCA_FOUND)
  FIND_PACKAGE(QCA REQUIRED)
ENDIF()

########################################################
# Source files

SET(AUTH_SAML2_SRCS
  qgsauthsaml2method.cpp
  qgsauthsaml2edit.cpp
)

SET(AUTH_SAML2_HDRS
  qgsauthsaml2method.h
  qgsauthsaml2edit.h
)

SET(AUTH_SAML2_MOC_HDRS
  qgsauthsaml2method.h
  qgsauthsaml2edit.h
)

SET(AUTH_SAML2_UIS qgsauthsaml2edit.ui)

# Common includes
INCLUDE_DIRECTORIES (
  ${CMAKE_CURRENT_BINARY_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}
)

IF(IN_QGIS_SRC)
  ### start: when in QGIS/src/auth ###
  INCLUDE_DIRECTORIES (
    ${CMAKE_SOURCE_DIR}/src/core
    ${CMAKE_SOURCE_DIR}/src/core/auth
    ${CMAKE_SOURCE_DIR}/src/core/geometry
    ${CMAKE_SOURCE_DIR}/src/auth/saml2
    ${CMAKE_SOURCE_DIR}/src/gui
    ${CMAKE_SOURCE_DIR}/src/gui/auth
    ${CMAKE_BINARY_DIR}/src/core
    ${CMAKE_BINARY_DIR}/src/gui
    ${CMAKE_BINARY_DIR}/src/ui
    ${CMAKE_BINARY_DIR}/src/ui/auth
    ${CMAKE_BINARY_DIR}/src/auth/saml2
  )
  ### end: when in QGIS/src/auth ###
ELSE(IN_QGIS_SRC)
  ### start: when standalone ###
  INCLUDE_DIRECTORIES (SYSTEM
    ${Qt5Sql_INCLUDE_DIRS}
    ${QT_INCLUDE_DIR}
    ${QGIS_INCLUDE_DIR}
  )
  ### end: when standalone ###
ENDIF(IN_QGIS_SRC)

INCLUDE_DIRECTORIES (SYSTEM
  ${QCA_INCLUDE_DIR}
)

QT4_WRAP_UI (AUTH_SAML2_UIS_H ${AUTH_SAML2_UIS})

QT4_WRAP_CPP(AUTH_SAML2_MOC_SRCS ${AUTH_SAML2_MOC_HDRS})

ADD_LIBRARY (saml2authmethod MODULE ${AUTH_SAML2_SRCS} ${AUTH_SAML2_HDRS} ${AUTH_SAML2_MOC_SRCS} ${AUTH_SAML2_UIS_H})

IF(IN_QGIS_SRC)
  # in QGIS source tree
  SET(SAML2_TARGET_LIBS
    qgis_core
    qgis_gui
    ${SAML2_TARGET_LIBS}
  )
ELSE(IN_QGIS_SRC)
  # outside QGIS source tree
  SET(SAML2_TARGET_LIBS
    ${QGIS_CORE_LIBRARY}
    ${QGIS_GUI_LIBRARY}
    ${QT_QTMAIN_LIBRARY}
    ${QT_QTXML_LIBRARY}
    ${QT_QTCORE_LIBRARY}
    ${QT_QTGUI_LIBRARY}
    ${QT_QTNETWORK_LIBRARY}
    ${QT_QTSVG_LIBRARY}
    ${SAML2_TARGET_LIBS}
  )
ENDIF(IN_QGIS_SRC)

TARGET_LINK_LIBRARIES (saml2authmethod
  ${SAML2_TARGET_LIBS}
)

if(WIN32)
  add_definitions(-DO2_DLL_EXPORT)
endif()

INSTALL(TARGETS saml2authmethod
  RUNTIME DESTINATION ${QGIS_PLUGIN_DIR}
  LIBRARY DESTINATION ${QGIS_PLUGIN_DIR})
