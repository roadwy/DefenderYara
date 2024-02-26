
rule Backdoor_BAT_XWormRAT_SP_MTB{
	meta:
		description = "Backdoor:BAT/XWormRAT.SP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 04 00 "
		
	strings :
		$a_03_0 = {73 0b 00 00 06 13 05 73 90 01 03 0a 13 06 11 06 72 90 01 03 70 6f 90 01 03 0a 13 07 11 04 14 18 8d 90 01 03 01 13 0a 11 0a 16 72 90 01 03 70 a2 11 0a 17 11 07 a2 11 0a 6f 90 01 03 0a 26 11 05 13 09 de 3f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}