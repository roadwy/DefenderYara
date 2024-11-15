
rule Trojan_Win64_ShellCodeRunner_VG_MTB{
	meta:
		description = "Trojan:Win64/ShellCodeRunner.VG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {50 72 69 76 61 74 65 20 4f 72 67 61 6e 69 7a 61 74 69 6f 6e 31 } //1 Private Organization1
		$a_01_1 = {39 31 31 33 31 30 32 34 35 39 35 34 30 33 31 34 58 52 31 } //1 9113102459540314XR1
		$a_01_2 = {4c 61 6e 67 66 61 6e 67 31 35 30 33 } //1 Langfang1503
		$a_01_3 = {4c 61 6e 67 66 61 6e 67 20 41 6c 6b 65 6d 20 4d 61 74 65 72 69 61 6c 20 54 65 63 68 6e 6f 6c 6f 67 79 20 43 6f 2e 2c 20 4c 74 64 2e 30 } //1 Langfang Alkem Material Technology Co., Ltd.0
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}