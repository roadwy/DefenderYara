
rule Backdoor_BAT_WebShell_AI_MTB{
	meta:
		description = "Backdoor:BAT/WebShell.AI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 04 00 "
		
	strings :
		$a_03_0 = {0a 06 06 6f 90 01 01 00 00 0a 07 16 07 8e 69 6f 90 01 01 00 00 0a 28 90 01 01 00 00 0a 72 90 01 02 00 70 6f 90 01 01 00 00 0a 02 6f 90 01 01 00 00 0a 26 2a 90 00 } //01 00 
		$a_01_1 = {38 00 65 00 64 00 62 00 32 00 33 00 31 00 36 00 30 00 64 00 31 00 35 00 37 00 31 00 61 00 30 00 } //00 00  8edb23160d1571a0
	condition:
		any of ($a_*)
 
}