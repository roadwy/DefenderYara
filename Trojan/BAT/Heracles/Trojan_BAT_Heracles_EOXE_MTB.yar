
rule Trojan_BAT_Heracles_EOXE_MTB{
	meta:
		description = "Trojan:BAT/Heracles.EOXE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 08 02 08 91 03 08 07 5d ?? ?? ?? ?? ?? 61 d2 9c 08 17 58 0c 08 02 8e 69 32 e5 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}