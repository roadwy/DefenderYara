
rule Trojan_Win32_Killav_GO{
	meta:
		description = "Trojan:Win32/Killav.GO,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {72 65 67 2e 65 78 65 20 41 44 44 20 22 48 4b 4c 4d 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 53 65 63 75 72 69 74 79 20 43 65 6e 74 65 72 22 } //01 00  reg.exe ADD "HKLM\Software\Microsoft\Security Center"
		$a_01_1 = {2f 76 20 41 6e 74 69 56 69 72 75 73 44 69 73 61 62 6c 65 4e 6f 74 69 66 79 20 2f 74 20 52 45 47 5f 44 57 4f 52 44 20 2f 64 20 30 78 30 30 30 30 30 30 30 31 20 2f 66 } //01 00  /v AntiVirusDisableNotify /t REG_DWORD /d 0x00000001 /f
		$a_01_2 = {2f 76 20 46 69 72 65 77 61 6c 6c 44 69 73 61 62 6c 65 4e 6f 74 69 66 79 20 2f 74 20 52 45 47 5f 44 57 4f 52 44 20 2f 64 20 30 78 30 30 30 30 30 30 30 31 20 2f 66 } //01 00  /v FirewallDisableNotify /t REG_DWORD /d 0x00000001 /f
		$a_01_3 = {2f 76 20 55 70 64 61 74 65 73 44 69 73 61 62 6c 65 4e 6f 74 69 66 79 20 2f 74 20 52 45 47 5f 44 57 4f 52 44 20 2f 64 20 30 78 30 30 30 30 30 30 30 31 20 2f 66 } //01 00  /v UpdatesDisableNotify /t REG_DWORD /d 0x00000001 /f
		$a_01_4 = {2f 76 20 41 6c 6c 6f 77 54 53 43 6f 6e 6e 65 63 74 69 6f 6e 73 20 2f 74 20 52 45 47 5f 44 57 4f 52 44 20 2f 64 20 30 78 30 30 30 30 30 30 30 31 20 2f 66 } //01 00  /v AllowTSConnections /t REG_DWORD /d 0x00000001 /f
		$a_01_5 = {2f 76 20 66 44 65 6e 79 54 53 43 6f 6e 6e 65 63 74 69 6f 6e 73 20 2f 74 20 52 45 47 5f 44 57 4f 52 44 20 2f 64 20 30 78 30 30 30 30 30 30 30 31 20 2f 66 } //01 00  /v fDenyTSConnections /t REG_DWORD /d 0x00000001 /f
		$a_01_6 = {2f 76 20 66 41 6c 6c 6f 77 54 6f 47 65 74 48 65 6c 70 20 2f 74 20 52 45 47 5f 44 57 4f 52 44 20 2f 64 20 30 78 30 30 30 30 30 30 30 31 20 2f 66 } //00 00  /v fAllowToGetHelp /t REG_DWORD /d 0x00000001 /f
	condition:
		any of ($a_*)
 
}