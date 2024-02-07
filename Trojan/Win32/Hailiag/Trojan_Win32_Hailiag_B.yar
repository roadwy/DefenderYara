
rule Trojan_Win32_Hailiag_B{
	meta:
		description = "Trojan:Win32/Hailiag.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 73 76 6f 68 6f 73 74 2e 65 78 65 } //01 00  \svohost.exe
		$a_01_1 = {26 73 68 61 64 61 3d 00 } //01 00  猦慨慤=
		$a_01_2 = {62 6d 70 75 72 6c 65 65 00 } //01 00 
		$a_01_3 = {2f 68 61 69 6c 69 61 6e 67 2e 61 73 70 3f 61 63 74 69 6f 6e 3d 69 6e 73 74 61 6c 6c 26 76 65 72 3d } //00 00  /hailiang.asp?action=install&ver=
	condition:
		any of ($a_*)
 
}