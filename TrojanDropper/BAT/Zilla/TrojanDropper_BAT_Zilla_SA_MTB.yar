
rule TrojanDropper_BAT_Zilla_SA_MTB{
	meta:
		description = "TrojanDropper:BAT/Zilla.SA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {67 65 74 5f 63 72 61 62 } //1 get_crab
		$a_81_1 = {44 6f 6e 27 74 20 6f 70 65 6e 20 74 68 69 73 20 66 69 6c 65 20 66 6f 72 20 79 6f 75 72 20 73 61 66 65 74 79 } //1 Don't open this file for your safety
		$a_01_2 = {52 65 67 20 61 64 64 20 22 48 4b 45 59 5f 4c 4f 43 41 4c 5f 4d 41 43 48 49 4e 45 5c 53 4f 46 54 57 41 52 45 5c 50 6f 6c 69 63 69 65 73 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 44 65 66 65 6e 64 65 72 22 20 2f 76 20 44 69 73 61 62 6c 65 41 6e 74 69 53 70 79 77 61 72 65 20 2f 74 20 52 45 47 5f 44 57 4f 52 44 20 2f 64 20 31 20 2f 66 } //1 Reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f
		$a_00_3 = {6e 65 74 20 75 73 65 72 20 25 75 73 65 72 6e 61 6d 65 25 20 2f 66 75 6c 6c 6e 61 6d 65 3a 22 4d 52 20 4b 52 41 42 53 20 57 41 53 20 48 45 52 45 21 22 } //1 net user %username% /fullname:"MR KRABS WAS HERE!"
		$a_03_4 = {63 6f 70 79 20 2f 79 20 22 25 74 65 6d 70 25 [0-0f] 2e 65 78 65 22 20 22 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 53 74 61 72 74 20 4d 65 6e 75 5c 50 72 6f 67 72 61 6d 73 5c 53 74 61 72 74 75 70 22 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_81_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}