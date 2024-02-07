
rule Ransom_Win32_Guperd{
	meta:
		description = "Ransom:Win32/Guperd,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 06 00 00 02 00 "
		
	strings :
		$a_01_0 = {6a 6d 71 61 70 66 33 6e 66 6c 61 74 65 69 33 35 2e 6f 6e 69 6f 6e 2e 6c 69 6e 6b } //02 00  jmqapf3nflatei35.onion.link
		$a_01_1 = {31 39 32 30 34 75 72 32 39 30 37 75 74 39 38 32 67 69 33 68 6f 6a 65 39 73 66 61 2e 65 78 65 } //02 00  19204ur2907ut982gi3hoje9sfa.exe
		$a_01_2 = {59 6f 75 20 68 61 76 65 20 6e 6f 74 20 70 61 69 64 20 74 68 65 20 72 61 6e 73 6f 6d 2e } //02 00  You have not paid the ransom.
		$a_01_3 = {43 6f 6e 67 72 61 74 73 3a 20 79 6f 75 27 76 65 20 70 61 69 64 2e 20 43 6c 69 63 6b 20 4f 4b 20 74 6f 20 64 65 63 72 79 70 74 20 79 6f 75 72 20 66 69 6c 65 73 20 28 54 68 69 73 20 77 69 6c 6c 20 74 61 6b 65 20 61 20 77 68 69 6c 65 20 73 6f 20 62 65 20 70 61 74 69 65 6e 74 29 2e } //02 00  Congrats: you've paid. Click OK to decrypt your files (This will take a while so be patient).
		$a_01_4 = {4d 6f 6e 65 72 6f 50 61 79 41 67 65 6e 74 2e 65 78 65 } //02 00  MoneroPayAgent.exe
		$a_01_5 = {52 45 47 20 41 44 44 20 22 48 4b 43 55 5c 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 22 20 2f 46 20 2f 74 20 52 45 47 5f 53 5a 20 2f 56 20 22 4d 6f 6e 65 72 6f 50 61 79 22 20 2f 44 } //00 00  REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /F /t REG_SZ /V "MoneroPay" /D
		$a_00_6 = {5d 04 00 00 f2 af } //03 80 
	condition:
		any of ($a_*)
 
}