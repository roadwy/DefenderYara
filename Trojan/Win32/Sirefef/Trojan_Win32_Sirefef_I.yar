
rule Trojan_Win32_Sirefef_I{
	meta:
		description = "Trojan:Win32/Sirefef.I,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 40 10 8b 70 48 8b 90 03 01 01 1d 3d 90 01 04 33 90 03 01 01 db ff 90 00 } //01 00 
		$a_03_1 = {8b 75 0c 83 c4 0c 8d 85 90 01 04 50 ff 75 90 01 01 c7 85 90 1b 00 01 00 01 00 89 75 0c ff 15 90 01 04 85 c0 7c 90 01 01 6a 40 68 00 10 00 00 8d 45 0c 50 90 00 } //01 00 
		$a_03_2 = {83 c4 0c 6a 40 68 00 10 00 00 8d 45 fc 50 57 8d 85 90 01 02 ff ff 50 ff 75 08 c7 85 90 01 02 ff ff 02 00 01 00 89 75 fc ff 15 90 01 04 85 c0 7c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Sirefef_I_2{
	meta:
		description = "Trojan:Win32/Sirefef.I,SIGNATURE_TYPE_ARHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 40 10 8b 70 48 8b 90 03 01 01 1d 3d 90 01 04 33 90 03 01 01 db ff 90 00 } //01 00 
		$a_03_1 = {8b 75 0c 83 c4 0c 8d 85 90 01 04 50 ff 75 90 01 01 c7 85 90 1b 00 01 00 01 00 89 75 0c ff 15 90 01 04 85 c0 7c 90 01 01 6a 40 68 00 10 00 00 8d 45 0c 50 90 00 } //01 00 
		$a_03_2 = {83 c4 0c 6a 40 68 00 10 00 00 8d 45 fc 50 57 8d 85 90 01 02 ff ff 50 ff 75 08 c7 85 90 01 02 ff ff 02 00 01 00 89 75 fc ff 15 90 01 04 85 c0 7c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}