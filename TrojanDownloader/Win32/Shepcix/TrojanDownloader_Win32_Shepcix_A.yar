
rule TrojanDownloader_Win32_Shepcix_A{
	meta:
		description = "TrojanDownloader:Win32/Shepcix.A,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 07 00 00 14 00 "
		
	strings :
		$a_02_0 = {68 74 74 70 3a 2f 2f 78 78 78 2e 90 02 08 2e 75 73 2f 63 65 73 68 69 2f 64 64 2e 74 78 74 90 00 } //01 00 
		$a_00_1 = {25 73 5c 75 70 64 61 74 61 78 2e 65 78 65 } //01 00  %s\updatax.exe
		$a_00_2 = {25 73 5c 25 64 2e 65 78 65 } //01 00  %s\%d.exe
		$a_00_3 = {74 6d 70 25 64 2e 74 65 6d 70 } //01 00  tmp%d.temp
		$a_00_4 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c 6c 73 73 61 73 73 2e 65 78 65 } //01 00  C:\WINDOWS\SYSTEM32\lssass.exe
		$a_00_5 = {63 3a 5c 5f 75 6e 69 6e 73 65 70 2e 62 61 74 } //01 00  c:\_uninsep.bat
		$a_00_6 = {3a 52 65 70 65 61 74 } //00 00  :Repeat
	condition:
		any of ($a_*)
 
}