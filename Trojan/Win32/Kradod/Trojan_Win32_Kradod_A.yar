
rule Trojan_Win32_Kradod_A{
	meta:
		description = "Trojan:Win32/Kradod.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {c6 45 ce 70 c6 45 cf 69 c6 45 d0 6e c6 45 d1 67 c6 45 d2 20 c6 45 d3 31 c6 45 d4 2e c6 45 d5 32 c6 45 d6 2e c6 45 d7 33 c6 45 d8 2e c6 45 d9 34 c6 45 da 20 c6 45 db 2d c6 45 dc 6e c6 45 dd 20 c6 45 de 31 c6 45 df 20 c6 45 e0 2d c6 45 e1 77 } //01 00 
		$a_03_1 = {c6 45 f5 75 c6 45 f6 63 c6 45 f7 6b c6 45 f8 90 01 01 c6 45 f9 90 01 01 c6 45 fa 90 01 01 e8 90 00 } //01 00 
		$a_00_2 = {73 76 63 68 6f 73 74 2e 65 78 65 20 2d 6b 20 6e 65 74 73 76 63 73 } //01 00  svchost.exe -k netsvcs
		$a_00_3 = {39 42 33 34 35 43 44 37 2d 42 30 30 36 2d 34 62 33 61 2d 41 46 43 36 2d 39 41 36 31 43 35 34 39 31 42 43 41 } //00 00  9B345CD7-B006-4b3a-AFC6-9A61C5491BCA
	condition:
		any of ($a_*)
 
}