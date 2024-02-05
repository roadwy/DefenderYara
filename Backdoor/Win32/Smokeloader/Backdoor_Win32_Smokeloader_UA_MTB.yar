
rule Backdoor_Win32_Smokeloader_UA_MTB{
	meta:
		description = "Backdoor:Win32/Smokeloader.UA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {0f b6 08 81 f1 90 01 04 8b 15 90 01 04 03 55 90 01 01 88 0a eb 90 0a 43 00 8b 55 90 01 01 83 c2 90 01 01 89 55 90 01 01 83 7d 90 01 04 a1 90 01 04 03 45 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}