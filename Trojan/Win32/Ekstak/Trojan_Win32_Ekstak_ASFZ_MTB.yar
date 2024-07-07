
rule Trojan_Win32_Ekstak_ASFZ_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.ASFZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 ec 0c 6a 05 c7 44 24 04 00 00 00 00 c7 44 24 08 08 00 00 00 e8 90 01 03 00 c7 44 24 08 00 00 00 00 ff 15 90 01 03 00 85 c0 74 90 00 } //2
		$a_03_1 = {6a 01 51 ff 15 90 01 03 00 8b c8 41 f7 d9 1b c9 23 c8 33 c0 85 c9 0f 95 c0 83 c4 0c c3 90 00 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}