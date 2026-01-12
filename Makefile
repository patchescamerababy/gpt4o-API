SRC_DIR := src/main/cpp
OBJ_DIR := build/obj
BIN_DIR := build/bin

SOURCES := $(wildcard $(SRC_DIR)/*.cpp)
OBJECTS := $(patsubst $(SRC_DIR)/%.cpp,$(OBJ_DIR)/%.o,$(SOURCES))

.PHONY: all clean all_static all_static_win check_dirs

# Linux 本机构建
CXX      := g++
CXXFLAGS := -std=c++20 -O3 -Wall -Wextra \
            -I/usr/local/include -I/usr/local/include/httplib -I/usr/local/include/nlohmann
LDFLAGS  := -L/usr/local/lib
LIBS     := -static -lstdc++ -lm -lcurl -lssl -lcrypto -lsqlite3 -lnghttp2 -lzstd -lz -lresolv -lpthread -ldl

TARGET   := $(BIN_DIR)/gpt4

all: $(TARGET)

$(TARGET): $(OBJECTS) | check_dirs
	$(CXX) $(OBJECTS) -o $@ $(LDFLAGS) $(LIBS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp | check_dirs
	$(CXX) $(CXXFLAGS) -c $< -o $@

check_dirs:
	@mkdir -p $(OBJ_DIR) $(BIN_DIR)

clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR)

# Linux 静态
all_static: CXXFLAGS += -static -pthread -fno-gnu-unique -D_GLIBCXX_USE_CXX11_ABI=1
all_static: LDFLAGS  += -static -pthread
all_static: LIBS     := -static -lstdc++ -lm -lcurl -lpsl -lidn2 -lunistring -lssl -lcrypto -lsqlite3 -lnghttp2 -lzstd -lz -lresolv -lpthread -ldl
all_static: $(OBJECTS) | check_dirs
	$(CXX) $(OBJECTS) -o $(BIN_DIR)/gpt4-static $(LDFLAGS) $(LIBS)

# Windows‑x86_64 交叉静态
CROSS   := x86_64-w64-mingw32
PREFIX  := /usr/$(CROSS)/static
WIN_CXX := $(CROSS)-g++

# ---- 编译阶段 ----
WIN_CXXFLAGS := -std=c++20 -O3 -Wall -Wextra \
                -DNGHTTP2_STATICLIB -DCURL_STATICLIB -DOPENSSL_STATIC \
                -I$(PREFIX)/include

# ---- 链接阶段 ----
WIN_LDFLAGS  := -static -static-libgcc -static-libstdc++ -L$(PREFIX)/lib
WIN_LIBS     := \
  -lcurl -lpsl -lidn2 -lunistring -lssl -lcrypto -lsqlite3 -lnghttp2 -lz -lzstd \
  -lwinpthread -lws2_32 -lcrypt32 -lbcrypt -lwinmm -lgdi32

WIN_TARGET   := $(BIN_DIR)/gpt4.exe

all_static_win: CXX      := $(WIN_CXX)
all_static_win: CXXFLAGS := $(WIN_CXXFLAGS)
all_static_win: LDFLAGS  := $(WIN_LDFLAGS)
all_static_win: LIBS     := $(WIN_LIBS)
all_static_win: $(OBJECTS) | check_dirs
	$(CXX) $(OBJECTS) -o $(WIN_TARGET) $(LDFLAGS) $(LIBS)
