
rule Trojan_Win32_Zenpak_DD_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.DD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {0f b6 0c 31 8b 75 c8 01 f1 81 e1 90 02 04 8b 75 ec 8b 5d cc 8a 1c 1e 8b 75 e4 32 1c 0e 8b 4d e8 8b 75 cc 88 1c 31 8b 4d f0 39 cf 8b 4d c4 89 55 d8 89 4d d4 89 7d dc 0f 84 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}