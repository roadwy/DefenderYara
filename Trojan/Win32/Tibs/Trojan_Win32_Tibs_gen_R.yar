
rule Trojan_Win32_Tibs_gen_R{
	meta:
		description = "Trojan:Win32/Tibs.gen!R,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 c2 8d 94 17 a1 22 00 00 81 90 03 05 05 ea 1f b1 ff ff c2 e1 4e 00 00 81 fa e1 4e 00 00 90 00 } //1
		$a_01_1 = {89 d7 f3 0f 2d cf 09 c9 74 02 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}