
rule Trojan_BAT_Heracles_SX_MTB{
	meta:
		description = "Trojan:BAT/Heracles.SX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {28 31 00 00 0a 06 28 0b 00 00 06 0b 07 2c 1f 07 74 34 00 00 02 02 ?? ?? ?? ?? ?? 14 16 16 6f 68 00 00 06 26 07 28 32 00 00 0a 26 16 6a 2a 17 6a 2a } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}