
rule Trojan_BAT_Zemsil_SO_MTB{
	meta:
		description = "Trojan:BAT/Zemsil.SO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {75 01 00 00 1b 0a 06 8e 69 8d 05 00 00 01 0b 16 0c 38 16 00 00 00 07 08 06 08 91 72 01 00 00 70 28 ?? ?? ?? 0a 59 d2 9c 08 17 58 0c 08 06 8e 69 32 e4 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}