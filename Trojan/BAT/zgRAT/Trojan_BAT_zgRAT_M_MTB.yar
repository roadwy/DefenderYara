
rule Trojan_BAT_zgRAT_M_MTB{
	meta:
		description = "Trojan:BAT/zgRAT.M!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 08 06 91 20 ?? ?? ?? a1 28 ?? ?? 00 06 06 19 5d 28 ?? ?? 00 0a 61 d2 9c 06 16 2d ?? 17 58 0a 06 08 8e 69 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}