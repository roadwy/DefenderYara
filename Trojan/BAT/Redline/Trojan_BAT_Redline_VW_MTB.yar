
rule Trojan_BAT_Redline_VW_MTB{
	meta:
		description = "Trojan:BAT/Redline.VW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_80_0 = {6e 6f 6d 69 6e 61 6c 6c 79 2e 72 75 2f 65 78 65 63 2f } //nominally.ru/exec/  01 00 
		$a_80_1 = {75 00 43 00 65 00 6e 00 77 00 7a 00 58 00 63 00 68 00 47 00 71 00 45 00 68 00 44 00 4c 00 43 00 71 00 4a 00 66 00 77 00 6d 00 78 00 47 00 50 00 } //u  01 00 
		$a_01_2 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //01 00  VirtualProtect
		$a_01_3 = {44 6f 77 6e 6c 6f 61 64 } //01 00  Download
		$a_80_4 = {47 68 6f 73 74 6c 79 43 72 79 70 74 2e 65 78 65 } //GhostlyCrypt.exe  00 00 
	condition:
		any of ($a_*)
 
}