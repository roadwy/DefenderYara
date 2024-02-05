
rule PWS_Win32_QQThief_C{
	meta:
		description = "PWS:Win32/QQThief.C,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {c6 45 ce 3f c6 45 cf 61 c6 45 d0 63 c6 45 d1 74 c6 45 d2 69 c6 45 d3 6f c6 45 d4 6e c6 45 d5 3d } //01 00 
		$a_01_1 = {c6 45 e9 73 c6 45 ea 6e c6 45 eb 69 c6 45 ec 66 c6 45 ed 66 } //01 00 
		$a_00_2 = {71 71 6c 6f 67 69 6e 2e 65 78 65 00 } //01 00 
		$a_00_3 = {44 4e 46 2e 65 78 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}