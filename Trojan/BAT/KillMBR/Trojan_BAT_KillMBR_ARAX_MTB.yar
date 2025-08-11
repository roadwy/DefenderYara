
rule Trojan_BAT_KillMBR_ARAX_MTB{
	meta:
		description = "Trojan:BAT/KillMBR.ARAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 06 07 8e 69 6f ?? ?? ?? 0a 8f ?? ?? ?? 01 28 ?? ?? ?? 0a 0c 09 08 28 ?? ?? ?? 0a 0d 11 04 17 58 13 04 11 04 1f 0e 32 d7 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_BAT_KillMBR_ARAX_MTB_2{
	meta:
		description = "Trojan:BAT/KillMBR.ARAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {5c 66 75 6b 2e 70 64 62 } //2 \fuk.pdb
		$a_00_1 = {5c 00 5c 00 2e 00 5c 00 50 00 68 00 79 00 73 00 69 00 63 00 61 00 6c 00 44 00 72 00 69 00 76 00 65 00 30 00 } //2 \\.\PhysicalDrive0
		$a_00_2 = {4d 00 42 00 52 00 20 00 68 00 61 00 73 00 20 00 62 00 65 00 65 00 6e 00 20 00 73 00 75 00 63 00 63 00 65 00 73 00 73 00 66 00 75 00 6c 00 6c 00 79 00 20 00 6f 00 76 00 65 00 72 00 77 00 72 00 69 00 74 00 74 00 65 00 6e 00 } //2 MBR has been successfully overwritten
	condition:
		((#a_01_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2) >=6
 
}
rule Trojan_BAT_KillMBR_ARAX_MTB_3{
	meta:
		description = "Trojan:BAT/KillMBR.ARAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_00_0 = {44 00 65 00 65 00 70 00 53 00 6b 00 79 00 42 00 6c 00 75 00 65 00 53 00 63 00 72 00 65 00 65 00 6e 00 4f 00 66 00 48 00 61 00 70 00 70 00 69 00 6e 00 65 00 73 00 73 00 } //2 DeepSkyBlueScreenOfHappiness
		$a_00_1 = {72 00 65 00 67 00 20 00 64 00 65 00 6c 00 65 00 74 00 65 00 20 00 48 00 4b 00 43 00 52 00 20 00 2f 00 66 00 } //2 reg delete HKCR /f
		$a_00_2 = {64 00 65 00 6c 00 65 00 74 00 65 00 73 00 20 00 70 00 68 00 79 00 73 00 69 00 63 00 61 00 6c 00 20 00 64 00 72 00 69 00 76 00 65 00 73 00 } //2 deletes physical drives
		$a_01_3 = {5c 6c 65 67 6a 6f 6e 67 2e 70 64 62 } //2 \legjong.pdb
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_01_3  & 1)*2) >=8
 
}
rule Trojan_BAT_KillMBR_ARAX_MTB_4{
	meta:
		description = "Trojan:BAT/KillMBR.ARAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 "
		
	strings :
		$a_01_0 = {5c 42 6f 6f 73 74 65 72 2e 70 64 62 } //2 \Booster.pdb
		$a_00_1 = {47 00 6f 00 6f 00 67 00 6c 00 65 00 5c 00 43 00 68 00 72 00 6f 00 6d 00 65 00 5c 00 55 00 73 00 65 00 72 00 20 00 44 00 61 00 74 00 61 00 5c 00 44 00 65 00 66 00 61 00 75 00 6c 00 74 00 5c 00 48 00 69 00 73 00 74 00 6f 00 72 00 79 00 } //2 Google\Chrome\User Data\Default\History
		$a_00_2 = {5c 00 5c 00 2e 00 5c 00 50 00 68 00 79 00 73 00 69 00 63 00 61 00 6c 00 44 00 72 00 69 00 76 00 65 00 30 00 } //2 \\.\PhysicalDrive0
		$a_01_3 = {47 65 74 57 69 46 69 50 61 73 73 77 6f 72 64 73 } //1 GetWiFiPasswords
		$a_01_4 = {47 65 74 4d 42 52 44 61 74 61 } //1 GetMBRData
	condition:
		((#a_01_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=8
 
}