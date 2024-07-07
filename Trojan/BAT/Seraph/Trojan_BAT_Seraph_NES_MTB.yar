
rule Trojan_BAT_Seraph_NES_MTB{
	meta:
		description = "Trojan:BAT/Seraph.NES!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {28 48 00 00 06 20 90 01 03 00 28 90 01 03 06 7e 90 01 03 04 28 90 01 03 06 28 90 01 03 06 0b 07 74 90 01 03 1b 0a 38 90 01 03 00 06 90 00 } //5
		$a_01_1 = {43 61 6c 63 75 6c 61 74 72 69 63 65 20 56 42 2e 65 78 65 } //1 Calculatrice VB.exe
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}