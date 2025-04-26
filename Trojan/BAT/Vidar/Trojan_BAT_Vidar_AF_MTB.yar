
rule Trojan_BAT_Vidar_AF_MTB{
	meta:
		description = "Trojan:BAT/Vidar.AF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 05 00 00 "
		
	strings :
		$a_02_0 = {fa 25 33 00 16 ?? ?? 01 ?? ?? ?? 19 ?? ?? ?? 02 ?? ?? ?? 02 ?? ?? ?? 01 ?? ?? ?? 17 ?? ?? ?? 0a ?? ?? ?? 01 ?? ?? ?? 02 ?? ?? ?? 01 } //10
		$a_80_1 = {77 65 62 43 6c 69 65 6e 74 } //webClient  3
		$a_80_2 = {45 6e 61 62 6c 65 56 69 73 75 61 6c 53 74 79 6c 65 73 } //EnableVisualStyles  3
		$a_80_3 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //DownloadData  3
		$a_80_4 = {64 69 73 63 6f 72 64 } //discord  3
	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3) >=22
 
}