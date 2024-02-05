
rule Trojan_Win32_CryptInject_YAC_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.YAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b c8 2b ca 8d 90 01 03 33 c9 89 90 01 02 fc ff ff 89 90 01 02 fc ff ff 85 d2 74 90 01 01 8a 90 01 03 30 14 19 83 ff 90 01 01 75 90 01 01 33 ff eb 90 01 01 47 41 3b 90 01 02 fc ff ff 72 90 01 01 8b 90 01 03 68 90 01 03 00 6a 40 50 53 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}