
rule Trojan_Win32_Amadey_NIT_MTB{
	meta:
		description = "Trojan:Win32/Amadey.NIT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 79 04 39 ba a0 00 00 00 72 14 8b 01 03 c7 39 82 a0 00 00 00 0f 82 0b 01 00 00 0f b7 42 06 46 83 c1 28 3b f0 72 d9 } //2
		$a_01_1 = {0f 8c 0a ff ff ff ff 75 d0 ff 15 5c f0 43 00 83 f8 ff 74 0e b8 01 00 00 00 5f 5e 8b e5 5d 8b e3 5b c3 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}