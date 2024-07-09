
rule Trojan_BAT_Heracles_PSKA_MTB{
	meta:
		description = "Trojan:BAT/Heracles.PSKA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 7e b5 00 00 0a 28 1a 00 00 0a 2c 06 7e ?? ?? ?? 0a 2a 02 28 ?? ?? ?? 0a 0a 28 ?? ?? ?? 0a 06 16 06 8e 69 6f b8 00 00 0a 2a } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}