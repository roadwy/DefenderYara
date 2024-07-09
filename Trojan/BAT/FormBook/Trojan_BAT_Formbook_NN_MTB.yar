
rule Trojan_BAT_Formbook_NN_MTB{
	meta:
		description = "Trojan:BAT/Formbook.NN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {00 00 09 17 58 0d 09 1d fe 02 16 fe 01 13 04 11 04 2d cf } //5
		$a_03_1 = {00 09 11 05 07 ?? ?? ?? ?? ?? 9c 00 11 05 17 58 13 05 11 05 11 04 fe 02 16 fe 01 13 06 11 06 2d df } //5
	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}