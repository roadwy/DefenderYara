
rule Trojan_Win32_SpyEyes_AM_MTB{
	meta:
		description = "Trojan:Win32/SpyEyes.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {8b 55 d0 81 32 90 02 04 8b 55 d0 81 72 04 90 02 04 ff 4d cc 8b 55 d0 83 c2 08 89 55 d0 83 7d cc 00 75 db 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}