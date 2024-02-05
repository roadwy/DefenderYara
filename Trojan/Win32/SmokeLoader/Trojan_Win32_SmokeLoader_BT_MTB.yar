
rule Trojan_Win32_SmokeLoader_BT_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.BT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {d3 e0 89 45 fc 8b 45 d4 01 45 fc 8b 45 f8 8b 4d ec 03 c6 89 45 e4 8b c6 d3 e8 03 45 d0 89 45 f4 8b 45 e4 31 45 fc 8b 45 f4 31 45 fc 89 1d 90 02 04 8b 45 fc 29 45 f0 8b 45 cc 29 45 f8 ff 4d e0 0f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}