
rule Trojan_BAT_Remcos_SMTN_MTB{
	meta:
		description = "Trojan:BAT/Remcos.SMTN!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 04 11 05 5a 13 04 11 05 17 58 13 05 11 05 02 31 ee } //1
		$a_01_1 = {08 09 58 0c 09 17 58 0d 09 02 31 f4 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}