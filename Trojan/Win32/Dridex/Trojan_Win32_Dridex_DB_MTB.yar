
rule Trojan_Win32_Dridex_DB_MTB{
	meta:
		description = "Trojan:Win32/Dridex.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {0f b6 d9 03 1d 90 01 04 0f b7 d0 03 d3 89 15 90 01 04 2a d0 80 c2 35 02 d2 02 ca 8a d0 2a 15 90 01 04 81 c7 6c 2b 06 01 80 ea 4b 89 3d 90 01 04 89 bc 2e a3 f0 ff ff 02 ca 8b 15 90 01 04 83 c6 04 81 fe 6d 10 00 00 0f 82 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Dridex_DB_MTB_2{
	meta:
		description = "Trojan:Win32/Dridex.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 08 00 00 03 00 "
		
	strings :
		$a_80_0 = {52 65 70 64 64 64 34 2e 70 64 62 } //Repddd4.pdb  03 00 
		$a_80_1 = {44 70 70 6f 74 74 6f 6e 45 72 72 } //DppottonErr  03 00 
		$a_80_2 = {47 65 74 52 61 77 49 6e 70 75 74 44 65 76 69 63 65 49 6e 66 6f 57 } //GetRawInputDeviceInfoW  03 00 
		$a_80_3 = {47 65 74 4b 65 79 4e 61 6d 65 54 65 78 74 41 } //GetKeyNameTextA  03 00 
		$a_80_4 = {53 65 74 75 70 44 69 47 65 74 44 65 76 69 63 65 49 6e 74 65 72 66 61 63 65 44 65 74 61 69 6c 41 } //SetupDiGetDeviceInterfaceDetailA  03 00 
		$a_80_5 = {4d 70 72 49 6e 66 6f 42 6c 6f 63 6b 52 65 6d 6f 76 65 } //MprInfoBlockRemove  03 00 
		$a_80_6 = {47 65 74 54 65 6d 70 46 69 6c 65 4e 61 6d 65 57 } //GetTempFileNameW  03 00 
		$a_80_7 = {57 72 69 74 65 50 72 69 76 61 74 65 50 72 6f 66 69 6c 65 53 74 72 75 63 74 57 } //WritePrivateProfileStructW  00 00 
	condition:
		any of ($a_*)
 
}