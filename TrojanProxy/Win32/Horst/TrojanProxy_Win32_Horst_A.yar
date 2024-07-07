
rule TrojanProxy_Win32_Horst_A{
	meta:
		description = "TrojanProxy:Win32/Horst.A,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 ws\CurrentVersion\Run
		$a_01_1 = {43 44 2d 45 43 44 32 2d 32 33 44 30 2d 42 41 43 34 2d 30 30 44 45 } //1 CD-ECD2-23D0-BAC4-00DE
		$a_01_2 = {33 36 34 35 46 42 43 44 2d 45 43 44 32 2d 32 33 44 30 2d 42 41 43 34 2d 30 30 44 45 34 35 33 44 45 46 36 } //1 3645FBCD-ECD2-23D0-BAC4-00DE453DEF6
		$a_01_3 = {2e 6e 76 73 76 63 62 } //1 .nvsvcb
		$a_01_4 = {31 2e 39 33 } //1 1.93
		$a_01_5 = {6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 ff 15 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}