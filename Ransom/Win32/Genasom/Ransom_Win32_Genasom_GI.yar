
rule Ransom_Win32_Genasom_GI{
	meta:
		description = "Ransom:Win32/Genasom.GI,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {74 61 73 6b 6b 69 6c 6c 20 2f 46 20 2f 49 4d 20 65 78 70 6c 6f 72 65 72 2e 65 78 65 } //01 00  taskkill /F /IM explorer.exe
		$a_00_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 6c 6f 67 6f 6e } //01 00  SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
		$a_01_2 = {77 69 6e 64 6f 77 73 73 65 63 75 72 69 74 79 } //01 00  windowssecurity
		$a_01_3 = {42 49 4f 53 2c 20 f1 20 ed e5 e2 ee e7 ec ee } //01 00 
		$a_01_4 = {e5 f2 20 ee ef eb e0 f7 e5 ed 2c 20 e2 f1 e5 } //01 00 
		$a_01_5 = {31 2e 20 c8 e7 e3 ee f2 ee e2 eb e5 ed e8 e5 } //00 00 
	condition:
		any of ($a_*)
 
}