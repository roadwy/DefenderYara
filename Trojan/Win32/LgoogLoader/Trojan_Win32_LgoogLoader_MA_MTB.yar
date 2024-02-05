
rule Trojan_Win32_LgoogLoader_MA_MTB{
	meta:
		description = "Trojan:Win32/LgoogLoader.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {89 45 c8 8b 45 c4 03 45 fc 89 45 cc 8b 45 f8 03 45 f4 39 45 d0 73 90 01 01 8b 45 c8 03 45 d0 8b 4d cc 03 4d d0 8a 11 88 10 8b 45 d0 83 c0 01 89 45 d0 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}