
rule Trojan_Win32_Autophyte_F_dha{
	meta:
		description = "Trojan:Win32/Autophyte.F!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 0d 00 00 "
		
	strings :
		$a_02_0 = {78 29 2e 4c 90 09 03 00 c7 } //1
		$a_02_1 = {5d a3 b5 d0 90 09 03 00 c7 } //1
		$a_02_2 = {67 f0 81 b7 90 09 03 00 c7 } //1
		$a_02_3 = {36 e5 d5 93 90 09 03 00 c7 } //1
		$a_00_4 = {0a 91 fb f2 98 29 10 72 5f 87 5f af 09 1e 11 50 } //1
		$a_00_5 = {02 84 ea cc ba 34 1c 74 49 87 78 92 0b 10 07 3e 51 } //1
		$a_00_6 = {0e 9b ff db ac 2f 1f 72 6d f4 } //1
		$a_00_7 = {0a 91 fb f6 8f 2b 03 47 4d 80 63 87 64 } //1
		$a_00_8 = {3e 9c fa d6 8e 29 04 79 2c } //1
		$a_00_9 = {1f 91 e8 ed 9a 23 1d 5c 49 8d 4a c6 } //1
		$a_00_10 = {1a a7 ce f1 9e 27 01 63 59 84 0b } //1
		$a_00_11 = {1f 91 e8 f3 9f 23 01 6e 7a 95 67 b3 01 3e 1a 11 51 } //1
		$a_00_12 = {3e 9b ec c9 8f 32 73 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_02_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1+(#a_00_10  & 1)*1+(#a_00_11  & 1)*1+(#a_00_12  & 1)*1) >=3
 
}