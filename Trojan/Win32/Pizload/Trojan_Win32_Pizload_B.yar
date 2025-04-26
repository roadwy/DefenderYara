
rule Trojan_Win32_Pizload_B{
	meta:
		description = "Trojan:Win32/Pizload.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {5c 64 72 69 76 65 72 73 5c 68 75 6f 78 69 6e 67 6a 68 2e 73 79 73 } //1 \drivers\huoxingjh.sys
		$a_01_1 = {75 6e 6b 6e 6f 77 6e 00 25 73 5c 64 72 69 76 65 72 73 5c 25 73 } //1
		$a_01_2 = {83 f8 40 0f 94 c2 c1 e1 06 83 e0 3f 0b c1 8b c8 2b ea 47 83 ff 04 75 1d } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}