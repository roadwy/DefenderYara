
rule Worm_Win32_Autorun_QH{
	meta:
		description = "Worm:Win32/Autorun.QH,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {55 00 53 00 42 00 4d 00 6f 00 6e 00 4d 00 75 00 74 00 65 00 78 00 32 00 2e 00 30 00 } //01 00  USBMonMutex2.0
		$a_01_1 = {25 53 79 73 74 65 6d 52 6f 6f 74 25 5c 73 79 73 74 65 6d 33 32 5c 75 73 62 6d 6f 6e 73 2e 65 78 65 } //01 00  %SystemRoot%\system32\usbmons.exe
		$a_03_2 = {52 45 43 59 43 4c 45 52 5c 52 45 43 59 43 4c 45 52 5c 61 75 74 6f 72 75 6e 2e 65 78 65 90 02 10 61 75 74 6f 72 75 6e 2e 69 6e 66 90 00 } //01 00 
		$a_03_3 = {44 6f 47 65 74 57 69 6e 6c 6f 67 6f 6e 50 69 64 21 90 02 04 53 65 44 65 62 75 67 50 72 69 76 69 6c 65 67 65 90 02 04 4f 70 65 6e 50 72 6f 63 65 73 73 21 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}