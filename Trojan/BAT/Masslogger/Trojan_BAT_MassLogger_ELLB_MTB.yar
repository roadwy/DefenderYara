
rule Trojan_BAT_MassLogger_ELLB_MTB{
	meta:
		description = "Trojan:BAT/MassLogger.ELLB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {5d 1c 58 13 3f 17 12 3b ?? ?? ?? ?? ?? 12 3b ?? ?? ?? ?? ?? 58 12 3b ?? ?? ?? ?? ?? 58 1f 7f 5b 58 13 40 11 40 1b fe 04 16 fe 01 13 41 12 3b } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}