
rule Trojan_Win32_GhostRAT_BS_MTB{
	meta:
		description = "Trojan:Win32/GhostRAT.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {8b 45 08 8a 10 8a 4d ef 32 d1 02 d1 88 10 40 89 45 08 c7 45 fc 01 00 00 00 b8 [0-04] c3 ff 45 e8 eb } //2
		$a_01_1 = {66 75 63 6b 79 6f 75 } //1 fuckyou
		$a_01_2 = {43 3a 5c 77 69 6e 64 6f 77 73 73 36 34 5c 63 6f 6d 70 75 74 65 72 2e 65 78 65 } //1 C:\windowss64\computer.exe
		$a_01_3 = {34 37 2e 39 33 2e 36 30 2e 36 33 3a 38 30 30 30 2f 65 78 70 6c 6f 72 6f 72 2e 65 78 65 } //1 47.93.60.63:8000/exploror.exe
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}