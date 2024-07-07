
rule Trojan_Win32_Gh0stLoader_A_dha{
	meta:
		description = "Trojan:Win32/Gh0stLoader.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_01_0 = {54 8d 9c 39 } //1
		$a_01_1 = {42 09 9e 5f } //1
		$a_01_2 = {e2 9a 5a f5 } //1
		$a_01_3 = {1b c2 10 3b } //1
		$a_01_4 = {71 a7 e8 fe } //1
		$a_01_5 = {81 8f f0 4e } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=4
 
}