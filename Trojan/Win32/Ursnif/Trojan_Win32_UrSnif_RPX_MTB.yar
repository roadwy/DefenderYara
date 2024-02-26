
rule Trojan_Win32_UrSnif_RPX_MTB{
	meta:
		description = "Trojan:Win32/UrSnif.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {59 8b 8d 68 fe ff ff 03 ce 2b c8 46 88 19 3b b5 6c fe ff ff 72 c9 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_UrSnif_RPX_MTB_2{
	meta:
		description = "Trojan:Win32/UrSnif.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {39 d2 74 01 ea 31 1a 81 ee 01 00 00 00 68 21 34 a3 ec 58 81 c2 04 00 00 00 01 f8 39 ca 75 e1 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_UrSnif_RPX_MTB_3{
	meta:
		description = "Trojan:Win32/UrSnif.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {89 45 f8 8b 45 f8 8b 48 1c 89 4d f4 ff 75 14 ff 75 10 ff 75 0c ff 75 08 ff 55 f4 89 45 fc 8b 45 fc 8b e5 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_UrSnif_RPX_MTB_4{
	meta:
		description = "Trojan:Win32/UrSnif.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {85 db 0f 84 50 00 00 00 56 89 2c 24 89 14 24 68 00 00 00 00 5a 01 c2 50 b8 00 00 00 00 01 d0 01 08 58 5a 83 ec 04 89 14 24 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_UrSnif_RPX_MTB_5{
	meta:
		description = "Trojan:Win32/UrSnif.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 0d 8b 54 24 44 8b 44 24 1c 88 1c 02 eb 0b 8b 44 24 44 8b 4c 24 1c 88 04 08 } //01 00 
		$a_01_1 = {8b 54 24 4c 52 68 00 30 00 00 68 00 d0 02 00 56 ff 15 } //00 00 
	condition:
		any of ($a_*)
 
}