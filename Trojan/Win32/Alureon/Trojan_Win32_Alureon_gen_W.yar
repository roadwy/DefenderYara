
rule Trojan_Win32_Alureon_gen_W{
	meta:
		description = "Trojan:Win32/Alureon.gen!W,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {8a d1 02 d0 30 14 31 83 c1 01 3b cf 72 f2 } //1
		$a_03_1 = {8d a4 24 00 00 00 00 80 34 38 ?? 83 c0 01 3b c6 72 f5 } //1
		$a_01_2 = {81 3f 53 54 53 54 75 } //1
		$a_01_3 = {61 66 66 69 64 3d 25 73 26 73 75 62 69 64 3d 25 73 26 64 61 74 61 3d 25 73 26 69 64 3d 25 73 } //1 affid=%s&subid=%s&data=%s&id=%s
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}