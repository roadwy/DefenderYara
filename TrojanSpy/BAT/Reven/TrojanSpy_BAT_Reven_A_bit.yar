
rule TrojanSpy_BAT_Reven_A_bit{
	meta:
		description = "TrojanSpy:BAT/Reven.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {75 73 62 53 70 72 65 61 64 65 72 } //1 usbSpreader
		$a_03_1 = {54 65 61 6d 52 65 76 65 6e 67 65 2d [0-08] 2e 70 64 62 } //1
		$a_00_2 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 45 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 5c 00 53 00 74 00 61 00 72 00 74 00 75 00 70 00 41 00 70 00 70 00 72 00 6f 00 76 00 65 00 64 00 5c 00 52 00 75 00 6e 00 } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}