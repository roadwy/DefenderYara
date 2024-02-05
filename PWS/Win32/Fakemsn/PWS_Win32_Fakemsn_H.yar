
rule PWS_Win32_Fakemsn_H{
	meta:
		description = "PWS:Win32/Fakemsn.H,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {69 00 6e 00 73 00 65 00 72 00 65 00 2e 00 70 00 68 00 70 00 } //01 00 
		$a_01_1 = {6d 73 6e 6d 73 67 72 2e 65 78 65 } //01 00 
		$a_01_2 = {0a 49 6e 76 69 73 69 76 65 6c 31 c0 03 00 } //00 00 
	condition:
		any of ($a_*)
 
}