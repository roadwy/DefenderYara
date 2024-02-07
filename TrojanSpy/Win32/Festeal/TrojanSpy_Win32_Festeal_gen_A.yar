
rule TrojanSpy_Win32_Festeal_gen_A{
	meta:
		description = "TrojanSpy:Win32/Festeal.gen!A,SIGNATURE_TYPE_PEHSTR,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {36 39 2e 34 36 2e 31 36 2e 31 39 31 } //01 00  69.46.16.191
		$a_01_1 = {30 38 38 46 41 38 34 30 2d 42 31 30 44 2d 31 31 44 33 2d 42 43 33 36 2d 30 30 36 30 36 37 37 30 39 36 37 34 } //01 00  088FA840-B10D-11D3-BC36-006067709674
		$a_01_2 = {73 65 6e 64 6d 61 69 6c } //01 00  sendmail
		$a_01_3 = {52 43 50 54 20 54 4f 3a } //01 00  RCPT TO:
		$a_01_4 = {4b 65 55 6e 73 74 61 63 6b 44 65 74 61 63 68 50 72 6f 63 65 73 73 } //01 00  KeUnstackDetachProcess
		$a_01_5 = {4b 65 53 74 61 63 6b 41 74 74 61 63 68 50 72 6f 63 65 73 73 } //01 00  KeStackAttachProcess
		$a_01_6 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 } //01 00  SYSTEM\CurrentControlSet\Services
		$a_01_7 = {47 65 74 57 69 6e 64 6f 77 73 44 69 72 65 63 74 6f 72 79 41 } //00 00  GetWindowsDirectoryA
	condition:
		any of ($a_*)
 
}