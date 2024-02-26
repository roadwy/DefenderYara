
rule Backdoor_BAT_WebShell_GMC_MTB{
	meta:
		description = "Backdoor:BAT/WebShell.GMC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {0d 08 09 6f 90 01 03 0a 26 08 02 6f 90 01 03 0a 6f 90 01 03 0a 26 08 07 6f 90 01 03 0a 26 08 6f 90 01 03 0a 26 09 6f 90 01 03 0a 13 04 09 6f 90 01 03 0a 02 6f 90 01 03 0a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}