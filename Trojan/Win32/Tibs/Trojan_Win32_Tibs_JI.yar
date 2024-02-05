
rule Trojan_Win32_Tibs_JI{
	meta:
		description = "Trojan:Win32/Tibs.JI,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {66 0f 6e e2 66 0f 7e e1 01 c1 31 d2 6a 7b db 1c 24 58 3d 00 00 00 80 75 } //01 00 
		$a_01_1 = {c6 45 ed 6b c6 45 ee 00 c6 45 ef 65 c6 45 f0 00 c6 45 f1 72 c6 45 f2 00 c6 45 f3 6e } //01 00 
	condition:
		any of ($a_*)
 
}