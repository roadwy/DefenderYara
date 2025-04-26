
rule Trojan_BAT_Heracles_GTT_MTB{
	meta:
		description = "Trojan:BAT/Heracles.GTT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 04 05 28 ?? ?? ?? 06 0a 0e 04 03 6f 9a 00 00 0a 59 0b 12 00 28 ?? ?? ?? 0a 0c 08 07 61 0c 03 06 07 28 ?? ?? ?? 06 00 2a } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}