
rule Trojan_Win32_Dridex_AD_MTB{
	meta:
		description = "Trojan:Win32/Dridex.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 05 00 00 "
		
	strings :
		$a_00_0 = {8d 8a 42 07 00 00 57 8b f8 2b f9 8d 74 3e b6 0f af c6 03 c1 0f af c6 03 c1 8d b4 08 dd 19 ff ff 8a d8 0f af c6 03 c1 } //10
		$a_80_1 = {4d 6f 73 74 2e 70 64 62 } //Most.pdb  3
		$a_80_2 = {55 6e 72 65 67 69 73 74 65 72 48 6f 74 4b 65 79 } //UnregisterHotKey  3
		$a_80_3 = {47 72 6f 77 6f 74 68 65 72 } //Growother  3
		$a_80_4 = {57 6f 72 64 46 6f 72 63 65 } //WordForce  3
	condition:
		((#a_00_0  & 1)*10+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3) >=22
 
}
rule Trojan_Win32_Dridex_AD_MTB_2{
	meta:
		description = "Trojan:Win32/Dridex.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_80_0 = {72 70 69 64 65 62 62 66 6c 6c 2e 70 64 62 } //rpidebbfll.pdb  3
		$a_80_1 = {53 65 74 75 70 44 69 45 6e 75 6d 44 65 76 69 63 65 49 6e 66 6f } //SetupDiEnumDeviceInfo  3
		$a_80_2 = {44 44 70 6c 73 6f 65 63 72 56 77 71 61 73 65 } //DDplsoecrVwqase  3
		$a_80_3 = {67 70 6f 69 72 65 65 } //gpoiree  3
		$a_80_4 = {47 65 74 49 66 54 61 62 6c 65 } //GetIfTable  3
		$a_80_5 = {52 65 67 4c 6f 61 64 41 70 70 4b 65 79 41 } //RegLoadAppKeyA  3
		$a_80_6 = {6c 64 6f 6c 6c 69 72 65 66 67 74 } //ldollirefgt  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3) >=21
 
}
rule Trojan_Win32_Dridex_AD_MTB_3{
	meta:
		description = "Trojan:Win32/Dridex.AD!MTB,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {29 3a 66 03 c9 66 03 ce b8 80 09 00 00 66 03 cf 8d 77 fe 66 2b c8 83 ea 08 0f b7 c1 03 f0 } //10
		$a_01_1 = {66 83 c1 27 0f b7 d3 66 03 c2 66 03 c6 66 03 c1 8d 4b ff 0f b7 c0 03 c8 8a 44 24 10 04 27 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}