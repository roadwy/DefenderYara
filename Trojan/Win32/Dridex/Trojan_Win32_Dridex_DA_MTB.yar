
rule Trojan_Win32_Dridex_DA_MTB{
	meta:
		description = "Trojan:Win32/Dridex.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b bc 2e f5 e4 ff ff 75 90 01 01 04 1e 02 c0 2a 05 90 01 04 02 c1 66 0f b6 d0 66 6b d2 03 66 2b 15 90 01 04 66 89 15 90 01 04 81 c7 d4 e0 08 01 89 3d 90 01 04 89 bc 2e f5 e4 ff ff 8a 15 90 01 04 66 8b 0d 90 01 04 8a c2 02 c1 83 c6 04 2c 02 81 fe 33 1c 00 00 0f 82 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
rule Trojan_Win32_Dridex_DA_MTB_2{
	meta:
		description = "Trojan:Win32/Dridex.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1c 00 1c 00 07 00 00 "
		
	strings :
		$a_02_0 = {8d 04 1f 03 f0 2b d6 83 ea 57 6b c2 56 89 15 90 01 04 2b c8 6b c7 56 89 0d 90 01 04 2b c8 2b d1 89 0d 90 01 04 8d 42 f7 03 c7 a3 90 01 04 33 c0 89 45 3c 8d 45 30 89 45 40 90 00 } //10
		$a_80_1 = {42 65 61 72 6d 61 73 73 } //Bearmass  3
		$a_80_2 = {43 61 73 65 6c 69 73 74 } //Caselist  3
		$a_80_3 = {43 6f 6d 6d 6f 6e 57 61 73 68 } //CommonWash  3
		$a_80_4 = {48 65 72 65 67 61 74 68 65 72 } //Heregather  3
		$a_80_5 = {4d 65 6c 6f 64 79 63 72 6f 73 73 } //Melodycross  3
		$a_80_6 = {57 6f 6f 64 67 69 72 6c } //Woodgirl  3
	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3) >=28
 
}