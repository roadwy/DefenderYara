
rule Backdoor_Win32_Adialer_J{
	meta:
		description = "Backdoor:Win32/Adialer.J,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 06 00 05 00 00 "
		
	strings :
		$a_01_0 = {7b 39 42 34 41 41 34 34 32 2d 39 45 42 46 2d 31 31 44 35 2d 38 43 31 31 2d 30 30 35 30 44 41 34 39 35 37 46 35 7d 20 3d 20 73 20 27 62 73 64 27 } //3 {9B4AA442-9EBF-11D5-8C11-0050DA4957F5} = s 'bsd'
		$a_01_1 = {68 74 74 70 3a 2f 2f 77 77 77 2e 74 72 61 66 66 69 63 6a 61 6d 2e 6e 6c 2f 3f 66 61 69 6c 65 64 3d 69 6e 69 74 69 61 6c 69 7a 65 } //3 http://www.trafficjam.nl/?failed=initialize
		$a_00_2 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 54 00 72 00 61 00 66 00 66 00 69 00 63 00 6a 00 61 00 6d 00 5c 00 43 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 69 00 6f 00 6e 00 } //2 Software\Trafficjam\Connection
		$a_01_3 = {53 74 61 72 74 20 50 61 67 65 } //1 Start Page
		$a_01_4 = {52 61 73 53 65 74 45 6e 74 72 79 50 72 6f 70 65 72 74 69 65 73 41 } //1 RasSetEntryPropertiesA
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_00_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}