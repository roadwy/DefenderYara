
rule Trojan_Win32_Smokeloader_GMH_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GMH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {33 f3 33 f0 2b fe 8b d7 c1 e2 90 01 01 89 54 24 90 01 01 8b 44 24 90 01 01 01 44 24 90 01 01 8b 5c 24 90 01 01 8b 0d 90 01 04 03 df 81 f9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}