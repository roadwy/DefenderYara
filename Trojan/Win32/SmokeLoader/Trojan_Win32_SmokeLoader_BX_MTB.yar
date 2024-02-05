
rule Trojan_Win32_SmokeLoader_BX_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.BX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {2b f8 89 45 0c 8b c7 c1 e0 04 89 7d e8 89 45 08 8b 45 e4 01 45 08 8b 45 e8 03 45 fc 89 45 f8 83 0d 90 02 04 ff 8b c7 c1 e8 05 03 45 e0 c7 05 90 02 04 19 36 6b ff 89 45 0c 33 45 f8 31 45 08 2b 75 08 8b 45 dc 29 45 fc ff 4d f4 0f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}