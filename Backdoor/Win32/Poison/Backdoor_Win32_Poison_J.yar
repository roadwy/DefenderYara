
rule Backdoor_Win32_Poison_J{
	meta:
		description = "Backdoor:Win32/Poison.J,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {8b d5 8b f8 33 c9 8a 04 31 30 04 0a 41 83 f9 90 01 01 7c 90 01 01 83 c2 90 01 01 4f 75 ec 90 00 } //1
		$a_02_1 = {8b c5 2b c1 8a 14 08 80 f2 90 01 01 88 11 41 4e 75 90 01 01 5f 5e 5d 5b c3 90 00 } //1
		$a_02_2 = {8b f5 bf 0a 00 00 00 ff d3 8b c8 b8 67 66 66 66 f7 e9 c1 fa 90 01 01 8b c2 83 c6 90 01 01 c1 e8 90 01 01 03 d0 4f 89 56 90 01 01 75 90 01 01 8b 44 24 90 01 01 81 c5 90 01 04 48 89 44 24 90 01 01 75 ca 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}