# Compiler and flags
CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2

# Linker libraries
LDLIBS = -llua -ldl -lm -lpthread -lldap -llber -lldns

# Source and object files
SRCS := \
	src/main.cpp \
	src/cli/arg_parser.cpp \
	src/engine/default_ports.cpp \
	src/engine/scan_engine.cpp \
	src/utils/helper_functions.cpp

OBJS = $(SRCS:.cpp=.o)

# Output binary
TARGET = hugin

# Default target
all: $(TARGET)

# Link
$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDLIBS)

# Compile
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Clean up
clean:
	rm -f $(OBJS)
