
rule Trojan_Win64_Winnti_P_dha{
	meta:
		description = "Trojan:Win64/Winnti.P!dha,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 04 00 00 "
		
	strings :
		$a_01_0 = {b0 99 41 83 fd 01 75 11 45 85 e4 7e 0c 30 07 48 ff c7 fe c0 48 ff cb 75 f4 } //10
		$a_01_1 = {49 63 47 3c 48 8b 8c 24 c0 00 00 00 48 03 c3 33 d2 48 89 06 48 89 48 30 48 8b 06 0f b7 48 14 66 3b 50 06 0f 83 93 00 00 00 4c 8b ac 24 c8 00 00 00 48 8d 7c 01 28 8b 07 85 c0 75 35 49 63 44 24 38 85 c0 7e 5e 8b 4f fc 41 b9 40 00 00 00 41 b8 00 10 00 00 48 03 4e 08 48 8b d0 48 8b d8 41 ff d6 4c 8b c3 33 d2 48 8b c8 89 47 f8 41 ff d5 eb 32 } //10
		$a_01_2 = {74 61 6e 67 6f 2e 64 6c 6c } //1 tango.dll
		$a_01_3 = {43 4f 4e 4e 45 43 54 20 25 73 3a 25 64 20 48 54 54 50 2f 31 2e 30 0d 0a 0d 0a } //1
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=11
 
}