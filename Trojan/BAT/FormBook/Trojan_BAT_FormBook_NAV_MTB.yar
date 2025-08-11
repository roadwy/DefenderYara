
rule Trojan_BAT_FormBook_NAV_MTB{
	meta:
		description = "Trojan:BAT/FormBook.NAV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_81_0 = {39 63 39 35 30 34 34 33 2d 31 62 38 64 2d 34 36 30 32 2d 61 33 65 65 2d 36 36 33 34 62 33 64 32 35 36 61 66 } //2 9c950443-1b8d-4602-a3ee-6634b3d256af
		$a_01_1 = {c3 f1 5e e0 06 8d 72 55 a2 5e d9 84 cb 62 02 84 99 d3 7d 32 23 01 44 44 10 65 c7 b6 fe 33 89 4f } //1
		$a_01_2 = {80 cc cc 59 ba cf d7 cb f7 3e cf fb 24 2c 99 74 57 fd 7f 75 55 77 2d 03 06 10 42 08 21 84 10 42 08 21 84 10 42 08 89 1f 1d cb 66 6d e6 15 b2 e3 3d 27 7b b0 9b 53 c7 bb 8e fe b6 e7 a8 2b 3c a3 } //1
	condition:
		((#a_81_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}