
rule Trojan_BAT_Nekark_NK_MTB{
	meta:
		description = "Trojan:BAT/Nekark.NK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {28 17 00 00 0a 6f 90 01 01 00 00 0a 0d 73 90 01 01 00 00 0a 13 04 11 04 72 90 01 01 00 00 70 6f 1a 00 00 0a 90 00 } //5
		$a_01_1 = {45 78 63 6c 75 73 69 6f 6e 50 61 74 68 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 ExclusionPath.Properties.Resources
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}