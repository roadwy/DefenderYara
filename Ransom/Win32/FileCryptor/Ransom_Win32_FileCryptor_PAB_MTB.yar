
rule Ransom_Win32_FileCryptor_PAB_MTB{
	meta:
		description = "Ransom:Win32/FileCryptor.PAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 08 00 00 "
		
	strings :
		$a_81_0 = {6e 75 52 5c 6e 6f 69 73 72 65 56 74 6e 65 72 72 75 43 5c 73 77 6f 64 6e 69 57 5c 74 66 6f 73 6f 72 63 69 4d 5c 65 72 61 77 74 66 6f 53 } //1 nuR\noisreVtnerruC\swodniW\tfosorciM\erawtfoS
		$a_81_1 = {68 74 74 70 3a 2f 2f 6d 61 69 6c 2e 72 6f 74 62 6c 61 75 2e 65 75 3a 31 35 33 33 32 2f } //1 http://mail.rotblau.eu:15332/
		$a_81_2 = {43 3a 5c 49 4e 54 45 52 4e 41 4c 5c 52 45 4d 4f 54 45 2e 45 58 45 } //1 C:\INTERNAL\REMOTE.EXE
		$a_81_3 = {47 6f 6f 64 20 4c 75 63 6b } //1 Good Luck
		$a_01_4 = {55 6e 68 6f 6f 6b 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 } //1 UnhookWindowsHookEx
		$a_01_5 = {44 65 72 52 6f 73 61 72 6f 74 65 50 61 6e 74 68 65 72 26 46 72 65 75 6e 64 65 7c 55 6e 73 69 63 68 74 62 61 72 6b 65 69 74 73 73 70 72 61 79 } //1 DerRosarotePanther&Freunde|Unsichtbarkeitsspray
		$a_01_6 = {74 75 73 72 6b 68 65 72 65 73 6f 50 } //1 tusrkheresoP
		$a_03_7 = {c6 45 fc 05 b9 90 01 04 8b 75 e4 8b c6 66 0f 1f 44 00 00 66 8b 10 66 3b 11 75 1e 66 85 d2 74 15 66 8b 50 02 66 3b 51 02 90 00 } //2
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_03_7  & 1)*2) >=7
 
}