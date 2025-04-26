
rule Trojan_Win32_RYUK_DSK_MTB{
	meta:
		description = "Trojan:Win32/RYUK.DSK!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 4d f4 c1 e9 05 ba 04 00 00 00 c1 e2 00 8b 75 0c 03 0c 16 33 c1 8b 4d f8 2b c8 89 4d f8 } //2
		$a_01_1 = {6a 00 75 00 76 00 69 00 6e 00 65 00 68 00 69 00 73 00 69 00 76 00 69 00 68 00 6f 00 68 00 69 00 63 00 65 00 66 00 6f 00 67 00 61 00 76 00 6f 00 } //2 juvinehisivihohicefogavo
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=2
 
}