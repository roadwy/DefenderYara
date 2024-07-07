
rule Backdoor_Win32_Bifrose_HU{
	meta:
		description = "Backdoor:Win32/Bifrose.HU,SIGNATURE_TYPE_PEHSTR,04 00 04 00 09 00 00 "
		
	strings :
		$a_01_0 = {75 08 3c 36 74 2c 34 36 eb 25 } //3
		$a_01_1 = {66 c7 44 24 18 d4 07 66 c7 44 24 1a 08 00 66 c7 44 24 1e 11 00 66 c7 44 24 20 14 00 } //1
		$a_01_2 = {75 09 66 81 7c 30 fe c7 05 74 15 } //2
		$a_01_3 = {3f 61 63 74 69 6f 6e 3d 75 70 64 61 74 65 64 26 68 6f 73 74 69 64 } //1 ?action=updated&hostid
		$a_01_4 = {25 73 5c 63 6f 6e 66 69 67 5c 25 73 6e 74 2e 64 6c } //1 %s\config\%snt.dl
		$a_01_5 = {6e 65 74 73 76 63 73 5f 30 78 25 64 } //1 netsvcs_0x%d
		$a_01_6 = {52 65 73 65 74 5f 53 53 44 54 } //1 Reset_SSDT
		$a_01_7 = {47 6c 6f 62 61 6c 5c 4e 65 74 50 61 73 73 } //1 Global\NetPass
		$a_01_8 = {5c 5c 2e 5c 52 45 53 53 5f 44 54 44 4f 53 } //1 \\.\RESS_DTDOS
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=4
 
}