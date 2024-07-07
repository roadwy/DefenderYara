
rule Trojan_BAT_Scarsi_MC_MTB{
	meta:
		description = "Trojan:BAT/Scarsi.MC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 04 06 18 5b 08 06 18 6f 90 01 03 0a 1f 10 28 90 01 03 0a 9c 06 18 58 0a 06 09 32 e3 90 00 } //5
		$a_01_1 = {53 6b 69 70 56 65 72 69 66 69 63 61 74 69 6f 6e } //1 SkipVerification
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}