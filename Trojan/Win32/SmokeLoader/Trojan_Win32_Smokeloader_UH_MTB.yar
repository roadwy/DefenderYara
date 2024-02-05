
rule Trojan_Win32_Smokeloader_UH_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.UH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8b 4d 08 03 4d fc 0f be 11 89 55 f8 e8 90 01 04 33 45 f8 8b 4d 08 03 4d fc 88 01 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}