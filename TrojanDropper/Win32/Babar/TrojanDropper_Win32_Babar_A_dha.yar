
rule TrojanDropper_Win32_Babar_A_dha{
	meta:
		description = "TrojanDropper:Win32/Babar.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {81 e1 00 ff ff ff 81 f9 00 16 45 bf 74 90 01 01 8b 55 f0 52 e8 90 00 } //1
		$a_01_1 = {c1 cf 08 be 00 ff 00 ff 23 fe c1 c0 08 ba ff 00 ff 00 23 c2 0b f8 } //1
		$a_01_2 = {8b 4e 0c 8b 56 10 8a 0c 11 8a 04 3b 32 c8 88 0f 8b 4e 0c 8b 56 10 88 04 11 ff 46 0c } //1
		$a_00_3 = {42 61 62 61 72 36 34 5c 42 61 62 61 72 36 34 5c } //1 Babar64\Babar64\
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1) >=3
 
}