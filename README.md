# Network
code for network such as tcp/ip

## some tools for writing network programs.
#### 在计算TCP数据包校验和的时候，原来数据包中填充的校验和不一定正确，因此不能用作判定校验和函数是否正确的标准。（wireshark自带的有验证校验和的功能，如果你要验证自己的程序是否正确，可以利用wireshark中的校验和验证功能和你相求的校验和是否一致。）（如果操作系统打开了校验和的功能，那么应用程序在发送数据包的时候不一定填入正确的校验和，TCP校验和交给硬件（网卡）去计算，然后填充）
