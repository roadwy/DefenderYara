
rule HackTool_Win64_SecureSockFunnel_ARA_MTB{
	meta:
		description = "HackTool:Win64/SecureSockFunnel.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 07 00 00 "
		
	strings :
		$a_01_0 = {5b 73 68 65 6c 6c 5d 20 73 65 73 73 69 6f 6e 20 63 6f 75 6c 64 20 6e 6f 74 20 67 65 74 20 66 69 62 65 72 20 72 65 6d 6f 74 65 20 65 6e 64 70 6f 69 6e 74 } //2 [shell] session could not get fiber remote endpoint
		$a_01_1 = {5b 73 68 65 6c 6c 5d 20 73 65 73 73 69 6f 6e 20 63 72 65 61 74 65 20 77 72 69 74 65 20 73 69 64 65 20 6f 66 20 6e 61 6d 65 64 20 70 69 70 65 } //2 [shell] session create write side of named pipe
		$a_01_2 = {67 61 74 65 77 61 79 5f 70 6f 72 74 73 } //2 gateway_ports
		$a_01_3 = {73 74 72 65 61 6d 5f 6c 69 73 74 65 6e 65 72 } //2 stream_listener
		$a_01_4 = {73 74 72 65 61 6d 5f 66 6f 72 77 61 72 64 65 72 } //2 stream_forwarder
		$a_01_5 = {5b 73 6f 63 6b 73 20 76 34 5d 20 73 65 73 73 69 6f 6e 20 42 69 6e 64 20 6e 6f 74 20 69 6d 70 6c 65 6d 65 6e 74 65 64 20 79 65 74 } //3 [socks v4] session Bind not implemented yet
		$a_01_6 = {5b 73 6f 63 6b 73 20 76 35 5d 20 73 65 73 73 69 6f 6e 20 42 69 6e 64 20 6e 6f 74 20 69 6d 70 6c 65 6d 65 6e 74 65 64 20 79 65 74 } //3 [socks v5] session Bind not implemented yet
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*3+(#a_01_6  & 1)*3) >=13
 
}