
rule Trojan_BAT_Zemsil_SA_MTB{
	meta:
		description = "Trojan:BAT/Zemsil.SA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {08 1a 5d 16 fe 01 0d 09 2c 0a 02 08 02 08 91 1f 3d 61 b4 9c 08 17 d6 0c 08 07 31 e4 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule Trojan_BAT_Zemsil_SA_MTB_2{
	meta:
		description = "Trojan:BAT/Zemsil.SA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 02 03 04 06 28 53 00 00 06 00 00 06 17 58 0a 06 02 6f 78 00 00 0a fe 04 0b 07 2d e3 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}