
rule PWS_Win32_QQpass_EC{
	meta:
		description = "PWS:Win32/QQpass.EC,SIGNATURE_TYPE_PEHSTR_EXT,07 00 06 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {69 64 2e 71 71 2e 63 6f 6d } //01 00 
		$a_01_1 = {61 71 2e 71 71 2e 63 6f 6d 2f 63 6e 2f 66 69 6e 64 70 73 77 2f 66 69 6e 64 70 73 77 5f 69 6e 64 65 78 } //01 00 
		$a_01_2 = {2e 77 6f 6f 64 63 2e 63 6f 6d 2f 71 71 2f 71 71 2e 61 73 70 } //01 00 
		$a_01_3 = {26 71 71 70 61 73 73 77 6f 72 64 3d } //01 00 
		$a_01_4 = {3f 71 71 6e 75 6d 62 65 72 3d } //01 00 
		$a_01_5 = {5c 42 69 6e 5c 51 51 2e 65 78 65 } //01 00 
		$a_01_6 = {d7 a3 c4 fa d2 bb b7 ab b7 e7 cb b3 a3 ac d0 c4 cf eb ca c2 b3 c9 a3 a1 } //00 00 
	condition:
		any of ($a_*)
 
}