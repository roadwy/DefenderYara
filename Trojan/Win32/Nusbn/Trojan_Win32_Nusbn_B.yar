
rule Trojan_Win32_Nusbn_B{
	meta:
		description = "Trojan:Win32/Nusbn.B,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 06 00 00 "
		
	strings :
		$a_01_0 = {3f 61 63 74 69 6f 6e 3d 67 65 74 45 78 65 4c 69 73 74 26 70 63 69 64 3d } //1 ?action=getExeList&pcid=
		$a_01_1 = {73 68 65 6c 6c 20 61 6d 20 73 74 61 72 74 20 2d 6e } //1 shell am start -n
		$a_01_2 = {6b 69 6c 6c 2d 73 65 72 76 65 72 } //1 kill-server
		$a_01_3 = {3f 61 63 74 69 6f 6e 3d 67 65 74 44 72 69 76 65 72 } //1 ?action=getDriver
		$a_01_4 = {56 00 49 00 44 00 5f 00 25 00 30 00 34 00 78 00 26 00 50 00 49 00 44 00 5f 00 25 00 30 00 34 00 78 00 } //1 VID_%04x&PID_%04x
		$a_01_5 = {32 32 32 2e 31 38 36 2e 36 30 2e 38 39 3a 31 31 32 33 } //5 222.186.60.89:1123
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*5) >=10
 
}