
rule PWS_Win32_Tibia_L{
	meta:
		description = "PWS:Win32/Tibia.L,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_02_0 = {53 56 83 c4 f4 8b f0 54 6a 00 68 90 01 04 e8 90 01 04 50 e8 90 01 04 8b 04 24 50 6a 00 68 ff 0f 1f 00 e8 90 01 04 8b d8 8d 44 24 04 50 6a 04 8d 44 24 10 50 56 53 e8 90 01 04 53 e8 90 01 04 8b 44 24 08 83 c4 0c 5e 5b c3 90 00 } //01 00 
		$a_00_1 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 73 76 63 68 6f 73 74 2e 62 61 74 } //01 00  C:\WINDOWS\svchost.bat
		$a_00_2 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 53 79 73 74 65 6d 33 32 5c 73 79 73 74 65 6d 2e 65 78 65 } //01 00  C:\WINDOWS\System32\system.exe
		$a_00_3 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 53 79 73 74 65 6d 33 32 5c 73 79 73 2e 65 78 65 } //01 00  C:\WINDOWS\System32\sys.exe
		$a_01_4 = {54 69 62 69 61 43 6c 69 65 6e 74 } //01 00  TibiaClient
		$a_01_5 = {54 69 62 69 61 2e 65 78 65 } //00 00  Tibia.exe
	condition:
		any of ($a_*)
 
}