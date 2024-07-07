
rule Trojan_Win32_Farfli_MY_MTB{
	meta:
		description = "Trojan:Win32/Farfli.MY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {89 ca c1 e9 16 8b 04 88 84 00 89 d1 c1 ea 10 83 e2 3f 8d 84 10 00 08 04 00 89 04 24 c1 e9 0d 83 e1 07 b8 01 00 00 00 d3 e0 88 44 24 04 e8 } //1
		$a_01_1 = {69 74 6f 6c 64 79 6f 75 73 6f } //1 itoldyouso
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}