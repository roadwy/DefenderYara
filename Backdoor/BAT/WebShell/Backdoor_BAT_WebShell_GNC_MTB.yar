
rule Backdoor_BAT_WebShell_GNC_MTB{
	meta:
		description = "Backdoor:BAT/WebShell.GNC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {0a 06 06 6f 90 01 03 0a 07 16 07 8e 69 6f 90 01 03 0a 28 90 01 03 0a 72 5d 00 00 70 6f 90 01 03 0a 02 6f 90 01 03 0a 26 2a 90 00 } //01 00 
		$a_03_1 = {41 70 70 5f 57 65 62 5f 90 02 16 2e 64 6c 6c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}