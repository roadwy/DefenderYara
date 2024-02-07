
rule HackTool_Win32_Wgdrop_A_MTB{
	meta:
		description = "HackTool:Win32/Wgdrop.A!MTB,SIGNATURE_TYPE_PEHSTR,17 00 17 00 0b 00 00 14 00 "
		
	strings :
		$a_01_0 = {42 79 20 57 69 6e 45 67 67 44 72 6f 70 } //01 00  By WinEggDrop
		$a_01_1 = {53 79 73 74 65 6d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 } //01 00  System\CurrentControlSet\Services
		$a_01_2 = {69 6e 73 74 61 6c 6c 20 53 65 72 76 69 63 65 4e 61 6d 65 20 44 69 73 70 6c 61 79 4e 61 6d 65 20 46 69 6c 65 4e 61 6d 65 } //01 00  install ServiceName DisplayName FileName
		$a_01_3 = {64 65 6c 65 74 65 20 53 65 72 76 69 63 65 4e 61 6d 65 } //01 00  delete ServiceName
		$a_01_4 = {46 49 4c 45 5f 47 45 4e 45 52 49 43 5f 45 58 45 43 55 54 45 } //01 00  FILE_GENERIC_EXECUTE
		$a_01_5 = {5c 44 65 76 69 63 65 5c 48 61 72 64 64 69 73 6b 56 6f 6c 75 6d 65 } //01 00  \Device\HarddiskVolume
		$a_01_6 = {4d 6f 64 69 66 79 20 46 69 6c 65 20 50 65 72 6d 69 73 73 69 6f 6e 20 4f 4b } //02 00  Modify File Permission OK
		$a_01_7 = {4b 69 6c 6c 20 54 68 65 20 50 72 6f 63 65 73 73 20 53 75 63 63 65 73 73 66 75 6c 6c 79 } //01 00  Kill The Process Successfully
		$a_01_8 = {53 45 4c 45 43 54 20 50 72 6f 63 65 73 73 49 64 2c 45 78 65 63 75 74 61 62 6c 65 50 61 74 68 20 46 52 4f 4d 20 57 69 6e 33 32 5f 50 72 6f 63 65 73 73 } //02 00  SELECT ProcessId,ExecutablePath FROM Win32_Process
		$a_01_9 = {49 6e 66 65 63 74 20 49 41 54 20 4f 4b } //01 00  Infect IAT OK
		$a_01_10 = {2f 49 6e 66 65 63 74 41 6c 6c 44 4c 4c } //00 00  /InfectAllDLL
	condition:
		any of ($a_*)
 
}