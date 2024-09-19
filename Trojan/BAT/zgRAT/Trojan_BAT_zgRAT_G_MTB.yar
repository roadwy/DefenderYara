
rule Trojan_BAT_ZgRAT_G_MTB{
	meta:
		description = "Trojan:BAT/ZgRAT.G!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 08 06 91 20 ?? ?? ?? 28 28 ?? 00 00 06 28 ?? 00 00 0a 59 d2 9c 06 17 58 0a 06 08 8e 69 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}