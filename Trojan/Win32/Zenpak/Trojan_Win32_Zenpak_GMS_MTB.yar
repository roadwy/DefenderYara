
rule Trojan_Win32_Zenpak_GMS_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.GMS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {76 45 41 69 5c 6a 31 4b 73 57 70 2e 70 64 62 } //01 00  vEAi\j1KsWp.pdb
		$a_80_1 = {73 68 65 2e 64 67 72 61 73 73 2e 6d 61 6e } //she.dgrass.man  01 00 
		$a_80_2 = {64 75 61 4a 74 68 65 79 2e 72 65 61 71 49 74 6f 67 65 74 68 65 72 } //duaJthey.reaqItogether  01 00 
		$a_80_3 = {35 4f 68 65 2e 61 62 6f 76 65 78 69 61 } //5Ohe.abovexia  01 00 
		$a_01_4 = {45 61 69 70 69 66 45 65 65 74 6f 69 6f } //00 00  EaipifEeetoio
	condition:
		any of ($a_*)
 
}