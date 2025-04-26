
rule Adware_Win32_Enumerate{
	meta:
		description = "Adware:Win32/Enumerate,SIGNATURE_TYPE_PEHSTR,02 00 02 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 65 6e 75 6d 65 72 61 74 65 5f 67 74 } //1 SOFTWARE\enumerate_gt
		$a_01_1 = {65 6e 75 6d 73 74 61 74 65 2e 63 6f 2e 6b 72 } //1 enumstate.co.kr
		$a_01_2 = {74 6f 70 73 65 61 72 63 68 2e 65 6e 75 6d 65 72 61 74 65 2e 63 6f 2e 6b 72 } //1 topsearch.enumerate.co.kr
		$a_01_3 = {65 6e 75 6d 73 74 5c 72 65 6c 65 61 73 65 5c 65 6e 75 6d 73 74 2e 70 64 62 } //1 enumst\release\enumst.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=2
 
}