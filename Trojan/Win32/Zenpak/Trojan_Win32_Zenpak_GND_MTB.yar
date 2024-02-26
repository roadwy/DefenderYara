
rule Trojan_Win32_Zenpak_GND_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.GND!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {33 44 44 4c 4a 46 38 2e 44 4c 4c } //01 00  3DDLJF8.DLL
		$a_01_1 = {75 71 76 65 72 79 74 68 61 74 62 65 67 69 6e 6e 69 6e 67 68 65 61 72 74 68 2e 73 69 78 74 68 } //01 00  uqverythatbeginninghearth.sixth
		$a_01_2 = {4a 77 66 72 75 69 74 66 75 6c 51 6d 65 54 } //01 00  JwfruitfulQmeT
		$a_01_3 = {4b 4f 6a 53 73 65 61 73 66 69 6c 6c 66 62 77 61 74 65 72 73 6d 6f 76 69 6e 67 } //01 00  KOjSseasfillfbwatersmoving
		$a_01_4 = {55 6e 64 65 72 39 73 65 65 64 6f 34 } //00 00  Under9seedo4
	condition:
		any of ($a_*)
 
}