
rule Trojan_BAT_Remcos_NEI_MTB{
	meta:
		description = "Trojan:BAT/Remcos.NEI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 09 07 8e 69 5d 91 06 09 91 61 d2 6f 90 01 01 00 00 0a 09 13 04 11 04 17 58 0d 09 06 8e 69 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}