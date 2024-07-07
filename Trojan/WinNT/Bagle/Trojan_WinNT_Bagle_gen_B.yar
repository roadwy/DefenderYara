
rule Trojan_WinNT_Bagle_gen_B{
	meta:
		description = "Trojan:WinNT/Bagle.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_00_0 = {c6 01 b8 c6 41 01 01 88 41 02 88 41 03 c6 41 04 c0 c6 41 05 c2 c6 41 06 08 88 41 07 8b 45 08 0f 22 c0 fb 83 45 10 04 } //1
		$a_00_1 = {75 18 c6 40 fb e9 8b 49 08 2b c8 89 48 fc 8b 45 08 66 ba eb f9 66 89 10 eb 3a 83 fa 02 75 18 c6 40 fb e9 } //1
		$a_02_2 = {83 7d e4 08 73 2c 8b 45 e4 ff 34 85 90 01 04 ff 75 e0 ff 15 90 01 04 59 59 85 c0 75 0e b8 22 00 00 c0 83 4d fc ff e9 90 01 01 00 00 00 ff 45 e4 eb ce 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1) >=1
 
}