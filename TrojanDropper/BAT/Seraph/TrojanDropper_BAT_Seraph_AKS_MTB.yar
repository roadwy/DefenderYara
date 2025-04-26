
rule TrojanDropper_BAT_Seraph_AKS_MTB{
	meta:
		description = "TrojanDropper:BAT/Seraph.AKS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {08 02 28 23 00 00 0a 7e ?? ?? ?? 04 15 16 28 ?? ?? ?? 0a 16 9a 28 ?? ?? ?? 06 28 ?? ?? ?? 0a de 40 } //5
		$a_00_1 = {24 64 37 35 35 63 35 37 35 2d 30 33 61 38 2d 34 65 34 61 2d 38 38 64 63 2d 33 37 36 38 64 63 31 34 62 32 61 37 } //1 $d755c575-03a8-4e4a-88dc-3768dc14b2a7
		$a_00_2 = {79 75 74 72 6e 6e 6f 2e 52 65 73 6f 75 72 63 65 73 } //1 yutrnno.Resources
	condition:
		((#a_03_0  & 1)*5+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=7
 
}