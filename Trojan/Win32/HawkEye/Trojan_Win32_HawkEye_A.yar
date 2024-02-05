
rule Trojan_Win32_HawkEye_A{
	meta:
		description = "Trojan:Win32/HawkEye.A,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 03 00 00 0a 00 "
		
	strings :
		$a_01_0 = {c1 e0 1f c1 f8 1f 25 96 30 07 77 c1 e1 18 c1 f9 1f 81 e1 20 83 b8 ed 33 c8 8b c2 c1 e0 1d c1 f8 1f 25 19 c4 6d 07 33 c8 8b c2 c1 e0 19 c1 f8 1f 25 90 41 dc 76 } //0a 00 
		$a_01_1 = {33 c8 8b c2 c1 e0 1a c1 f8 1f 25 c8 20 6e 3b 33 c8 8b c2 c1 e0 1e c1 f8 1f 25 2c 61 0e ee 33 c8 8b c2 c1 e0 1b c1 f8 1f 25 64 10 b7 1d } //0a 00 
		$a_01_2 = {33 c8 8b c2 c1 e0 1c c1 f8 1f 25 32 88 db 0e c1 ea 08 33 c8 33 d1 46 } //00 00 
	condition:
		any of ($a_*)
 
}