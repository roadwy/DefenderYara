
rule Trojan_Win32_Miancha_JHAA_MTB{
	meta:
		description = "Trojan:Win32/Miancha.JHAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {99 f7 f9 8b 45 f4 89 55 90 01 01 8d 0c 32 8a 14 32 88 10 8b 55 90 01 01 88 19 8b 4d 90 01 01 0f b6 00 03 ca 0f b6 d3 03 c2 8b df 99 f7 fb 8a 04 32 30 01 ff 45 fc 8b 45 fc 3b 45 10 7c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}