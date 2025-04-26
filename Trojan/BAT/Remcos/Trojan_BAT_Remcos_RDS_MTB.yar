
rule Trojan_BAT_Remcos_RDS_MTB{
	meta:
		description = "Trojan:BAT/Remcos.RDS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {13 07 11 07 06 16 06 8e 69 6f 25 00 00 0a 11 06 6f 26 00 00 0a 0b } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}