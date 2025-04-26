
rule Trojan_BAT_Vidar_ZMO_MTB{
	meta:
		description = "Trojan:BAT/Vidar.ZMO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 02 00 00 "
		
	strings :
		$a_03_0 = {61 69 13 26 08 17 58 20 ?? ?? ?? 00 5d 0c 09 06 08 91 58 20 ?? ?? ?? 00 5d 0d 06 08 91 13 27 06 08 06 09 91 9c 06 09 11 27 9c 06 08 91 06 09 91 58 } //5
		$a_03_1 = {13 35 03 11 34 91 13 36 06 11 35 91 13 ?? 11 36 11 37 61 d2 13 36 03 11 34 11 36 9c de 05 } //4
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*4) >=9
 
}