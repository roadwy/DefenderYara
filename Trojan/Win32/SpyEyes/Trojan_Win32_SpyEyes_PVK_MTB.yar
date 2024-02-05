
rule Trojan_Win32_SpyEyes_PVK_MTB{
	meta:
		description = "Trojan:Win32/SpyEyes.PVK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_02_0 = {89 08 8b 4d fc 5f 5e 89 58 04 33 cd 5b e8 90 01 04 c9 c2 04 00 90 09 0c 00 8b 8d 90 01 01 fb ff ff 8b 85 90 01 01 fb ff ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}