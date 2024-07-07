
rule Trojan_Win32_Deozp_A{
	meta:
		description = "Trojan:Win32/Deozp.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {00 76 65 72 73 69 6f 6e 3d 25 75 26 69 64 3d 25 75 00 } //1 瘀牥楳湯┽♵摩┽u
		$a_03_1 = {0f b7 06 c1 ea 06 69 d2 90 01 04 03 ca 0f b7 56 02 03 c1 89 4d 08 0f b7 4e 06 8b d9 c1 e3 10 33 d9 83 fb 01 77 90 01 01 8b d9 c1 e3 18 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}