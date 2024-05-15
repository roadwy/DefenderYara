
rule Backdoor_BAT_XWormRAT_J_MTB{
	meta:
		description = "Backdoor:BAT/XWormRAT.J!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {04 20 e8 03 00 00 d8 28 } //02 00 
		$a_03_1 = {0a 0b 07 14 73 90 01 03 0a 20 10 27 00 00 20 98 3a 00 00 6f 90 00 } //02 00 
		$a_01_2 = {07 6c 23 00 00 00 00 00 00 d0 41 5b 13 04 12 04 28 } //00 00 
	condition:
		any of ($a_*)
 
}