
rule Trojan_Win32_Drixed_RPZ_MTB{
	meta:
		description = "Trojan:Win32/Drixed.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {89 20 b9 02 00 00 00 e2 11 4a 4a 89 e8 50 8f 05 90 01 04 e9 31 fc ff ff c3 42 83 c2 07 29 c2 8d 05 90 01 04 31 38 83 e8 09 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Drixed_RPZ_MTB_2{
	meta:
		description = "Trojan:Win32/Drixed.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {80 bd ff fe ff ff 54 89 85 f4 fe ff ff 75 4a 80 bd 00 ff ff ff 45 75 41 80 bd 01 ff ff ff 53 75 38 80 bd 02 ff ff ff 54 75 2f 80 bd 03 ff ff ff 41 75 26 80 bd 04 ff ff ff 50 75 1d 80 bd 05 ff ff ff 50 75 14 b8 01 00 00 00 80 bd 0a ff ff ff 00 89 85 f0 fe ff ff 74 0a } //00 00 
	condition:
		any of ($a_*)
 
}