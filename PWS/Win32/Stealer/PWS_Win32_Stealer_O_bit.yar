
rule PWS_Win32_Stealer_O_bit{
	meta:
		description = "PWS:Win32/Stealer.O!bit,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {49 6e 66 6f 4c 6f 67 73 2f 50 43 } //1 InfoLogs/PC
		$a_01_1 = {57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 Windows\CurrentVersion\Run
		$a_03_2 = {68 6f 73 74 90 02 10 2e 68 6f 73 74 6c 61 6e 64 2e 70 72 6f 2f 90 02 10 2e 65 78 65 90 00 } //1
		$a_01_3 = {64 72 69 76 65 72 71 75 65 72 79 20 3e 3e } //1 driverquery >>
		$a_01_4 = {56 4d 77 61 72 65 00 00 43 69 72 72 75 73 20 4c 6f 67 69 63 } //1
		$a_01_5 = {66 74 70 35 37 2e 68 6f 73 74 6c 61 6e 64 2e 72 75 } //1 ftp57.hostland.ru
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}