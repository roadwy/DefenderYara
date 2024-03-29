
rule Trojan_Win32_VBInject_S{
	meta:
		description = "Trojan:Win32/VBInject.S,SIGNATURE_TYPE_PEHSTR_EXT,08 00 07 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {00 52 6a 01 6a ff 6a 20 ff 15 90 01 01 11 40 00 c7 45 fc 90 01 01 00 00 00 90 09 0c 00 c7 45 fc 90 01 01 00 00 00 8b 15 3c 90 01 01 90 03 01 01 41 42 90 00 } //01 00 
		$a_03_1 = {73 0c c7 85 90 01 01 ff ff ff 00 00 00 00 eb 0c ff 15 90 01 01 90 03 01 01 10 11 40 00 89 85 90 01 01 ff ff ff 8b 45 90 01 01 8b 0d 20 90 01 01 41 00 8b 14 81 52 e8 90 01 02 ff ff 90 00 } //01 00 
		$a_03_2 = {fd ff ff 02 00 01 00 c7 45 fc 90 01 01 00 00 00 8d 90 09 03 00 c7 85 90 00 } //05 00 
		$a_03_3 = {81 e1 ff 00 00 00 ff 15 90 01 01 11 40 00 8b 55 90 04 01 03 b4 b8 bc 8b 4a 0c 8b 90 01 02 fe ff ff 88 04 11 c7 45 fc 90 01 01 00 00 00 e9 90 01 01 f6 ff ff c7 45 fc 90 01 01 00 00 00 90 00 } //01 00 
		$a_03_4 = {c7 45 fc 03 00 00 00 c7 45 90 01 01 00 00 00 00 c7 45 90 01 01 02 00 00 00 8d 45 90 01 36 83 c4 0c c7 45 fc 04 00 00 00 68 ff 00 00 00 8b 55 90 01 2f c7 45 fc 05 00 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}