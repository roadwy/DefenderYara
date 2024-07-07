
rule PWS_Win32_Dofoil_E{
	meta:
		description = "PWS:Win32/Dofoil.E,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {2f 77 65 62 6c 6f 67 73 2f 72 65 63 76 2e 70 68 70 } //1 /weblogs/recv.php
		$a_01_1 = {48 65 6c 6c 6f 20 63 72 75 65 6c 20 77 6f 72 6c 64 } //1 Hello cruel world
		$a_00_2 = {69 00 65 00 5f 00 69 00 6e 00 6a 00 65 00 63 00 74 00 6f 00 72 00 5f 00 25 00 64 00 2e 00 74 00 78 00 74 00 } //1 ie_injector_%d.txt
		$a_00_3 = {65 00 6c 00 65 00 76 00 61 00 74 00 65 00 64 00 20 00 72 00 65 00 73 00 74 00 61 00 72 00 74 00 } //1 elevated restart
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=3
 
}