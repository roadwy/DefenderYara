
rule Trojan_Win32_Vidar_ASAF_MTB{
	meta:
		description = "Trojan:Win32/Vidar.ASAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 45 08 03 85 90 01 02 ff ff 8a 08 88 0a eb 90 01 01 8b 55 08 03 95 90 01 02 ff ff 0f b6 02 8b 8d 90 01 02 ff ff 33 84 8d 90 01 02 ff ff 8b 95 90 01 02 ff ff 03 95 90 01 02 ff ff 88 02 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}