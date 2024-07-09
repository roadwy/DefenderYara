
rule Trojan_Win32_Dridex_PA_MTB{
	meta:
		description = "Trojan:Win32/Dridex.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {45 53 54 41 50 50 50 65 78 65 } //1 ESTAPPPexe
		$a_81_1 = {51 44 64 65 66 61 75 6c 74 73 } //1 QDdefaults
		$a_81_2 = {6e 75 6d 62 65 72 74 68 65 6d } //1 numberthem
		$a_81_3 = {46 47 45 52 4e 2e 70 64 62 } //1 FGERN.pdb
		$a_81_4 = {4f 72 61 63 6c 65 20 43 6f 72 70 6f 72 61 74 69 6f 6e } //1 Oracle Corporation
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}
rule Trojan_Win32_Dridex_PA_MTB_2{
	meta:
		description = "Trojan:Win32/Dridex.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_01_0 = {47 73 70 2e 70 64 62 } //1 Gsp.pdb
		$a_01_1 = {51 00 66 00 72 00 65 00 65 00 46 00 79 00 63 00 6b 00 68 00 49 00 47 00 } //1 QfreeFyckhIG
		$a_01_2 = {67 00 70 00 6d 00 67 00 70 00 6d 00 67 00 70 00 6d 00 2e 00 64 00 6c 00 6c 00 } //2 gpmgpmgpm.dll
		$a_03_3 = {8b 44 24 10 8a 8c 24 ?? ?? ?? ?? 80 f1 46 8a [0-06] 8b b4 24 ?? ?? ?? ?? 81 f6 ?? ?? ?? ?? 88 8c 24 ?? ?? ?? ?? 8b bc 24 ?? ?? ?? ?? 81 c7 ?? ?? ?? ?? 89 bc 24 ?? ?? ?? ?? 8a 88 ?? ?? ?? ?? 8b 7c 24 ?? 89 bc 24 ?? ?? ?? ?? 8b 5c 24 ?? 89 9c 24 ?? ?? ?? ?? 28 d1 88 4c 04 ?? 83 c0 01 39 f0 89 44 24 ?? 75 } //3
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_03_3  & 1)*3) >=7
 
}
rule Trojan_Win32_Dridex_PA_MTB_3{
	meta:
		description = "Trojan:Win32/Dridex.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_02_0 = {55 8b ec 57 a1 ?? ?? ?? 00 a3 ?? ?? ?? 00 8b 0d ?? ?? ?? 00 89 0d ?? ?? ?? 00 8b 15 ?? ?? ?? 00 8b 02 a3 ?? ?? ?? 00 8b 0d ?? ?? ?? 00 81 e9 fc 1a 01 00 89 0d ?? ?? ?? 00 8b 0d ?? ?? ?? 00 81 c1 fc 1a 01 00 a1 ?? ?? ?? 00 a3 ?? ?? ?? 00 b8 13 00 01 00 90 08 00 03 a1 ?? ?? ?? 00 31 0d ?? ?? ?? 00 [0-f0] 8b ff c7 05 ?? ?? ?? 00 00 00 00 00 a1 ?? ?? ?? 00 01 05 ?? ?? ?? 00 8b ff 8b 15 ?? ?? ?? 00 a1 ?? ?? ?? 00 89 02 5f 5d c3 } //10
		$a_00_1 = {8d 84 02 92 27 01 00 8b 4d 08 03 01 8b 55 08 89 02 8b 45 08 8b 08 81 e9 92 27 01 00 8b 55 08 89 0a } //1
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*1) >=11
 
}