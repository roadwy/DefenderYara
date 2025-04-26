
rule PWS_Win32_Zbot_gen_GOB{
	meta:
		description = "PWS:Win32/Zbot.gen!GOB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {89 5f 14 89 5f 08 89 5f 18 c7 47 2c 02 00 00 00 8b 46 08 89 46 10 8b 46 18 89 5e 14 3b c3 7d 05 f7 d8 89 46 18 8b 46 18 8b c8 f7 d9 1b c9 83 e1 b9 53 83 c1 71 53 89 4e 04 53 83 f8 02 } //1
		$a_00_1 = {66 00 69 00 64 00 65 00 6c 00 69 00 74 00 79 00 } //1 fidelity
		$a_00_2 = {62 00 69 00 74 00 63 00 6f 00 69 00 6e 00 2d 00 71 00 74 00 } //1 bitcoin-qt
		$a_01_3 = {55 4e 4c 4f 43 4b } //1 UNLOCK
		$a_01_4 = {76 6e 63 00 6c 6f 63 61 6c 68 6f 73 74 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}