
rule Trojan_Win32_FakeDoc_DSK_MTB{
	meta:
		description = "Trojan:Win32/FakeDoc.DSK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_02_0 = {8a 91 d8 a2 90 01 02 30 90 01 02 9b 90 00 } //2
		$a_02_1 = {83 f9 20 75 90 01 01 33 c9 eb 90 01 01 41 40 3b c6 72 90 00 } //1
		$a_02_2 = {8a 81 18 c5 90 01 02 30 82 d8 bd 90 00 } //2
		$a_02_3 = {83 f9 20 75 90 01 01 33 c9 eb 90 01 01 41 42 3b d6 72 90 00 } //1
	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*1+(#a_02_2  & 1)*2+(#a_02_3  & 1)*1) >=3
 
}