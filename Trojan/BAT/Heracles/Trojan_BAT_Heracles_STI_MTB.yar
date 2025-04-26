
rule Trojan_BAT_Heracles_STI_MTB{
	meta:
		description = "Trojan:BAT/Heracles.STI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {1f 1a 28 01 00 00 0a 72 ?? ?? ?? 70 28 02 00 00 0a 0a 06 72 ?? ?? ?? 70 28 02 00 00 0a 0b 73 03 00 00 0a 25 72 2f 00 00 70 6f 04 00 00 0a 25 72 ?? ?? ?? 70 6f 05 00 00 0a 25 17 6f 06 00 00 0a } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}