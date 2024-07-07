
rule Trojan_BAT_Remcos_AP_MTB{
	meta:
		description = "Trojan:BAT/Remcos.AP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0c 08 11 04 16 73 90 01 01 02 00 0a 0d 09 07 6f 90 01 01 02 00 0a 07 6f 90 01 01 02 00 0a 13 05 de 1f 09 6f 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}