
rule Trojan_Win32_Tibs_JK{
	meta:
		description = "Trojan:Win32/Tibs.JK,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {56 ff 75 08 ff d1 c9 c2 04 00 ba 90 01 04 90 03 0e 02 66 0f 6e 90 01 01 66 0f 7e 90 01 01 01 c1 89 d1 31 d2 41 42 81 fa 90 00 } //01 00 
	condition:
		any of ($a_*)
 
}