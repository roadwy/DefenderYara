
rule Trojan_BAT_Stealer_LAS_MTB{
	meta:
		description = "Trojan:BAT/Stealer.LAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {6f ab 00 00 0a 06 04 8c 5c 00 00 01 6f ab 00 00 0a 06 05 8c 58 00 00 01 6f ?? ?? ?? 0a 7e 54 00 00 04 1f 12 28 9e 00 00 06 6f ?? ?? ?? 0a 14 06 6f ?? ?? ?? 0a 6f a8 00 00 0a } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}