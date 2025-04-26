
rule Trojan_BAT_Remcos_SPDF_MTB{
	meta:
		description = "Trojan:BAT/Remcos.SPDF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 "
		
	strings :
		$a_01_0 = {61 11 0d 59 20 00 01 00 00 58 20 ff 00 00 00 5f 13 10 07 11 0c 11 10 d2 9c } //6
	condition:
		((#a_01_0  & 1)*6) >=6
 
}