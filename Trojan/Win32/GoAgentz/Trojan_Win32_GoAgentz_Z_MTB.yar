
rule Trojan_Win32_GoAgentz_Z_MTB{
	meta:
		description = "Trojan:Win32/GoAgentz.Z!MTB,SIGNATURE_TYPE_PEHSTR,0b 00 0b 00 0b 00 00 "
		
	strings :
		$a_01_0 = {63 6c 69 65 6e 74 20 66 69 6e 69 73 68 65 64 } //1 client finished
		$a_01_1 = {73 65 72 76 65 72 20 66 69 6e 69 73 68 65 64 } //1 server finished
		$a_01_2 = {6b 65 79 20 65 78 70 61 6e 73 69 6f 6e } //1 key expansion
		$a_01_3 = {65 78 74 65 6e 64 65 64 20 6d 61 73 74 65 72 20 73 65 63 72 65 74 } //1 extended master secret
		$a_01_4 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //1 VirtualAlloc
		$a_01_5 = {47 6f 20 62 75 69 6c 64 69 6e 66 } //1 Go buildinf
		$a_01_6 = {75 73 65 72 6e 61 6d 65 } //1 username
		$a_01_7 = {70 61 73 73 77 6f 72 64 } //1 password
		$a_01_8 = {41 64 64 72 50 6f 72 74 } //1 AddrPort
		$a_01_9 = {73 6f 63 6b 61 64 64 72 } //1 sockaddr
		$a_01_10 = {48 8b 84 24 48 05 00 00 31 c9 87 88 30 05 00 00 90 b9 01 00 00 00 f0 0f c1 88 68 03 00 00 48 8b 84 24 28 05 00 00 48 8b 0d 54 dc 4e 00 48 89 0c 24 48 89 44 24 08 e8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=11
 
}