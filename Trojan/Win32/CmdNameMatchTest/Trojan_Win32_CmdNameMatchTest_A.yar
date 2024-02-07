
rule Trojan_Win32_CmdNameMatchTest_A{
	meta:
		description = "Trojan:Win32/CmdNameMatchTest.A,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_00_0 = {61 00 34 00 31 00 65 00 38 00 63 00 31 00 62 00 2d 00 65 00 34 00 63 00 31 00 2d 00 34 00 64 00 65 00 36 00 2d 00 39 00 38 00 30 00 61 00 2d 00 39 00 38 00 34 00 38 00 34 00 32 00 34 00 35 00 64 00 36 00 62 00 34 00 } //00 00  a41e8c1b-e4c1-4de6-980a-98484245d6b4
	condition:
		any of ($a_*)
 
}