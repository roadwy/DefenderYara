
rule Backdoor_Win32_Ripinip_C{
	meta:
		description = "Backdoor:Win32/Ripinip.C,SIGNATURE_TYPE_PEHSTR_EXT,17 00 16 00 06 00 00 0a 00 "
		
	strings :
		$a_01_0 = {43 68 61 6e 67 65 53 65 72 76 69 63 65 43 6f 6e 66 69 67 32 41 } //0a 00  ChangeServiceConfig2A
		$a_00_1 = {25 53 79 73 74 65 6d 52 6f 6f 74 25 5c 53 79 73 74 65 6d 33 32 5c 73 76 63 68 6f 73 74 2e 65 78 65 20 2d 6b 20 6e 65 74 73 76 63 73 } //01 00  %SystemRoot%\System32\svchost.exe -k netsvcs
		$a_00_2 = {52 65 6d 6f 74 65 20 49 50 52 49 50 20 53 65 72 76 69 63 65 } //01 00  Remote IPRIP Service
		$a_00_3 = {5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 25 64 } //01 00  \\.\PhysicalDrive%d
		$a_00_4 = {6c 65 64 5c 00 00 00 00 63 79 63 00 63 3a 5c 72 65 00 00 00 5c 6e 69 70 72 70 2e 64 6c 6c 00 00 } //01 00 
		$a_00_5 = {53 65 72 76 69 63 65 44 6c 6c 00 00 50 61 72 61 6d 65 74 65 72 73 5c 00 53 74 61 72 74 00 00 00 72 69 70 5c 00 00 00 00 69 63 65 73 5c 49 70 00 } //00 00 
	condition:
		any of ($a_*)
 
}