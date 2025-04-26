
rule Worm_Win32_Autorun_WN{
	meta:
		description = "Worm:Win32/Autorun.WN,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {48 00 44 00 44 00 46 00 69 00 6c 00 65 00 2e 00 63 00 6f 00 6d 00 } //1 HDDFile.com
		$a_00_1 = {61 00 75 00 74 00 6f 00 72 00 75 00 6e 00 2e 00 69 00 6e 00 66 00 } //1 autorun.inf
		$a_00_2 = {5b 00 61 00 75 00 74 00 6f 00 72 00 75 00 6e 00 5d 00 } //1 [autorun]
		$a_01_3 = {5c 48 61 63 6b 69 6e 67 20 54 6f 6f 6c 73 5c 4b 45 59 4c 4f 47 47 45 52 20 50 52 4f 4a 45 43 54 } //2 \Hacking Tools\KEYLOGGER PROJECT
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*2) >=4
 
}