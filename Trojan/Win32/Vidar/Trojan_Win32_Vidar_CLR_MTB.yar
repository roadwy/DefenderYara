
rule Trojan_Win32_Vidar_CLR_MTB{
	meta:
		description = "Trojan:Win32/Vidar.CLR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 39 35 2e 32 31 36 2e 31 36 34 2e 32 38 3a 38 30 } //01 00  http://95.216.164.28:80
		$a_01_1 = {73 6f 66 74 6f 6b 6e 33 2e 64 6c 6c } //01 00  softokn3.dll
		$a_01_2 = {6e 73 73 33 2e 64 6c 6c } //01 00  nss3.dll
		$a_01_3 = {6d 6f 7a 67 6c 75 65 2e 64 6c 6c } //01 00  mozglue.dll
		$a_01_4 = {66 72 65 65 62 6c 33 2e 64 6c 6c } //01 00  freebl3.dll
		$a_01_5 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e } //01 00  SOFTWARE\Microsoft\Windows NT\CurrentVersion
		$a_01_6 = {48 41 52 44 57 41 52 45 5c 44 45 53 43 52 49 50 54 49 4f 4e 5c 53 79 73 74 65 6d 5c 43 65 6e 74 72 61 6c 50 72 6f 63 65 73 73 6f 72 5c 30 } //01 00  HARDWARE\DESCRIPTION\System\CentralProcessor\0
		$a_81_7 = {53 65 6c 65 63 74 20 2a 20 46 72 6f 6d 20 57 69 6e 33 32 5f 4f 70 65 72 61 74 69 6e 67 53 79 73 74 65 6d } //01 00  Select * From Win32_OperatingSystem
		$a_81_8 = {53 65 6c 65 63 74 20 2a 20 46 72 6f 6d 20 41 6e 74 69 56 69 72 75 73 50 72 6f 64 75 63 74 } //00 00  Select * From AntiVirusProduct
	condition:
		any of ($a_*)
 
}