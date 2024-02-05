
rule Trojan_Win32_VBInjector{
	meta:
		description = "Trojan:Win32/VBInjector,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {fc ff 8b d0 8d 4d 90 01 01 e8 90 01 02 fc ff 68 90 01 04 8d 45 90 01 01 50 e8 90 01 04 50 6a 00 e8 90 01 04 89 90 00 } //01 00 
		$a_03_1 = {85 c0 74 02 eb 90 04 01 03 32 38 3b 83 c8 ff 85 c0 74 90 04 01 03 29 2f 32 c7 90 01 02 90 02 03 01 00 00 00 c7 90 01 02 90 02 03 02 00 00 00 8d 45 90 00 } //00 00 
		$a_00_2 = {78 59 01 00 01 00 01 00 04 00 } //00 01 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_VBInjector_2{
	meta:
		description = "Trojan:Win32/VBInjector,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {01 dd 05 3c 90 01 02 00 dc 1d 90 01 01 11 40 00 df e0 9e 73 05 e9 90 01 01 01 00 00 e8 90 01 04 a1 38 90 01 02 00 99 6a 07 59 f7 f9 a3 38 90 01 02 00 6a 00 6a 00 6a 00 6a 00 ff 35 38 90 01 02 00 90 00 } //01 00 
		$a_03_1 = {eb 04 83 65 90 01 01 00 83 7d 90 01 01 0a 74 05 e8 90 01 02 fd ff c7 45 ec 90 01 03 02 db 45 ec dd 5d 90 01 01 dd 45 90 01 01 83 3d 00 90 01 02 00 00 75 08 dc 35 90 01 02 40 00 eb 11 ff 35 90 01 02 40 00 ff 35 90 01 02 40 00 e8 90 01 02 fd ff df e0 a8 0d 90 00 } //01 00 
		$a_03_2 = {75 08 dc 35 90 01 01 10 40 00 eb 11 ff 35 90 01 01 10 40 00 ff 35 90 01 01 10 40 00 e8 90 01 03 ff df e0 a8 0d 0f 85 90 01 01 01 00 00 90 09 1d 00 c7 45 90 01 05 db 45 90 01 01 dd 9d 90 01 02 ff ff dd 85 90 01 02 ff ff 83 3d 00 90 01 02 00 00 90 00 } //01 00 
		$a_03_3 = {99 2b c2 d1 f8 89 45 90 01 01 83 3d 10 f0 42 00 00 75 1b 68 10 f0 42 00 68 90 01 01 14 40 00 e8 90 01 02 fd ff c7 85 90 01 01 fd ff ff 10 f0 42 00 eb 0a c7 85 90 01 01 fd ff ff 10 f0 42 00 90 09 0a 00 c7 45 90 01 03 90 04 01 02 81 84 00 8b 45 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}