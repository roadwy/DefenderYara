
rule Trojan_BAT_Remcos_AJG_MTB{
	meta:
		description = "Trojan:BAT/Remcos.AJG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0d 16 13 04 2b 1b 08 11 04 9a 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 02 33 04 16 0a 2b 0d 11 04 17 58 13 04 11 04 08 8e 69 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}