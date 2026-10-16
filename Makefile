CXX = g++
CXXFLAGS = -std=c++20 -Wall -Wextra -O3

TARGET = tun
SRCS = src/tun.cpp src/packet.cpp src/tunnel.cpp src/gtp.cpp src/arp.cpp src/upf.cpp
OBJS = $(SRCS:.cpp=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(OBJS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)