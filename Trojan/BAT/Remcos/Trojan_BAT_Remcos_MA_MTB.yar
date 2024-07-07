
rule Trojan_BAT_Remcos_MA_MTB{
	meta:
		description = "Trojan:BAT/Remcos.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {08 13 05 16 13 06 11 05 12 06 28 90 01 03 0a 00 08 07 11 04 18 6f 90 01 03 0a 1f 10 28 90 01 03 0a 6f 90 01 03 0a 00 de 0d 90 00 } //5
		$a_01_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 38 00 30 00 2e 00 36 00 36 00 2e 00 37 00 35 00 2e 00 33 00 37 00 2f 00 } //5 http://80.66.75.37/
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}