
rule Trojan_BAT_Remcos_MVR_MTB{
	meta:
		description = "Trojan:BAT/Remcos.MVR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 04 72 29 00 00 70 6f 05 00 00 0a 13 05 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}