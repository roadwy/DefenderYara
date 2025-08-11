
rule Trojan_BAT_Stealer_SUG_MTB{
	meta:
		description = "Trojan:BAT/Stealer.SUG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 8d 1d 00 00 01 13 04 7e ?? ?? ?? 04 02 1a 58 11 04 16 08 28 d0 00 00 0a 28 23 00 00 0a 11 04 16 11 04 8e 69 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}