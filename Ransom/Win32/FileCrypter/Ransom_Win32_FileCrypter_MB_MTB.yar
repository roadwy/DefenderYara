
rule Ransom_Win32_FileCrypter_MB_MTB{
	meta:
		description = "Ransom:Win32/FileCrypter.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 09 00 00 02 00 "
		
	strings :
		$a_81_0 = {73 63 68 74 61 73 6b 73 20 2f 43 72 65 61 74 65 20 2f 53 43 20 4d 49 4e 55 54 45 20 2f 54 4e } //02 00  schtasks /Create /SC MINUTE /TN
		$a_81_1 = {77 6d 69 63 20 53 48 41 44 4f 57 43 4f 50 59 20 44 45 4c 45 54 45 } //02 00  wmic SHADOWCOPY DELETE
		$a_81_2 = {77 62 61 64 6d 69 6e 20 44 45 4c 45 54 45 20 53 59 53 54 45 4d 53 54 41 54 45 42 41 43 4b 55 50 } //02 00  wbadmin DELETE SYSTEMSTATEBACKUP
		$a_81_3 = {62 63 64 65 64 69 74 2e 65 78 65 20 2f 20 73 65 74 7b 20 64 65 66 61 75 6c 74 20 7d 20 62 6f 6f 74 73 74 61 74 75 73 70 6f 6c 69 63 79 20 69 67 6e 6f 72 65 61 6c 6c 66 61 69 6c 75 72 65 73 } //02 00  bcdedit.exe / set{ default } bootstatuspolicy ignoreallfailures
		$a_81_4 = {62 63 64 65 64 69 74 2e 65 78 65 20 2f 20 73 65 74 7b 20 64 65 66 61 75 6c 74 20 7d 20 72 65 63 6f 76 65 72 79 65 6e 61 62 6c 65 64 20 4e 6f } //02 00  bcdedit.exe / set{ default } recoveryenabled No
		$a_81_5 = {76 73 73 61 64 6d 69 6e 2e 65 78 65 20 44 65 6c 65 74 65 20 53 68 61 64 6f 77 73 20 2f 20 41 6c 6c 20 2f 20 51 75 69 65 74 } //01 00  vssadmin.exe Delete Shadows / All / Quiet
		$a_81_6 = {48 4f 57 20 54 4f 20 52 45 53 54 4f 52 45 20 46 49 4c 45 53 2e 54 58 54 } //01 00  HOW TO RESTORE FILES.TXT
		$a_81_7 = {41 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 20 77 65 72 65 20 65 6e 63 72 79 70 74 65 64 } //01 00  All your files were encrypted
		$a_81_8 = {2e 6d 6f 75 73 65 } //00 00  .mouse
		$a_00_9 = {5d 04 00 00 1c 45 04 80 5c 38 00 00 } //1d 45 
	condition:
		any of ($a_*)
 
}