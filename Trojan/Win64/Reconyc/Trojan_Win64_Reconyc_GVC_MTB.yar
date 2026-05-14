
rule Trojan_Win64_Reconyc_GVC_MTB{
	meta:
		description = "Trojan:Win64/Reconyc.GVC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,21 00 21 00 07 00 00 "
		
	strings :
		$a_01_0 = {35 37 30 30 31 35 37 30 30 32 35 36 30 30 31 6e 65 74 73 68 } //1 570015700256001netsh
		$a_01_1 = {50 61 79 6c 6f 61 64 20 64 65 63 72 79 70 74 65 64 3a } //1 Payload decrypted:
		$a_01_2 = {61 64 76 66 69 72 65 77 61 6c 6c 66 69 72 65 77 61 6c 6c 61 64 64 72 75 6c 65 64 69 72 3d 69 6e 61 63 74 69 6f 6e 3d 61 6c 6c 6f 77 70 72 6f 74 6f 63 6f 6c 3d 54 43 50 } //1 advfirewallfirewalladdruledir=inaction=allowprotocol=TCP
		$a_01_3 = {52 65 67 69 73 74 72 79 20 52 75 6e 20 4b 65 79 47 68 6f 73 74 20 53 63 68 65 64 75 6c 65 64 20 54 61 73 6b 57 69 6e 6c 6f 67 6f 6e 20 55 73 65 72 69 6e 69 74 43 4f 4d 20 48 69 6a 61 63 6b 69 6e 67 47 6c 6f 62 61 6c 5c 53 74 65 61 6c 74 68 50 61 63 6b 65 72 4d 75 74 65 78 5f 39 41 38 42 37 43 } //15 Registry Run KeyGhost Scheduled TaskWinlogon UserinitCOM HijackingGlobal\StealthPackerMutex_9A8B7C
		$a_01_4 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 6c 6f 67 6f 6e 55 73 65 72 69 6e 69 74 } //15 Software\Microsoft\Windows\CurrentVersion\RunSOFTWARE\Microsoft\Windows NT\CurrentVersion\WinlogonUserinit
		$a_01_5 = {73 63 68 74 61 73 6b 73 2f 43 72 65 61 74 65 2f 46 2f 53 43 4f 4e 4c 4f 47 4f 4e 2f 54 4e 2f 54 52 2f 52 4c 48 49 47 48 45 53 54 } //15 schtasks/Create/F/SCONLOGON/TN/TR/RLHIGHEST
		$a_01_6 = {73 63 68 74 61 73 6b 73 2f 44 65 6c 65 74 65 2f 46 2f 54 4e 2f 43 72 65 61 74 65 2f 53 43 4f 4e 4c 4f 47 4f 4e 2f 54 52 2f 52 4c 48 49 47 48 45 53 54 45 } //15 schtasks/Delete/F/TN/Create/SCONLOGON/TR/RLHIGHESTE
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*15+(#a_01_4  & 1)*15+(#a_01_5  & 1)*15+(#a_01_6  & 1)*15) >=33
 
}