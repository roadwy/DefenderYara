
rule Trojan_Win32_Matcash_gen_K{
	meta:
		description = "Trojan:Win32/Matcash.gen!K,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {6a 0a 5f f7 f7 80 c2 30 88 54 35 e8 46 85 c0 75 ed 3b ce 7e 1e 2b ce 89 4d 7c 8b d1 c1 e9 02 8d 7c 35 e8 b8 30 30 30 30 } //1
		$a_01_1 = {83 7d f0 00 74 1a 80 7d 13 0a 75 05 c6 06 0a eb 1c 6a 01 6a ff ff 75 14 e8 e0 fe ff ff } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}