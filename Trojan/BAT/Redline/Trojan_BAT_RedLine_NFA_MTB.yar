
rule Trojan_BAT_RedLine_NFA_MTB{
	meta:
		description = "Trojan:BAT/RedLine.NFA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_03_0 = {07 06 08 06 8e 69 5d 91 02 08 91 61 d2 6f ?? 00 00 0a 08 17 58 0c 08 02 8e 69 } //1
		$a_01_1 = {36 66 32 66 61 38 62 37 2d 63 63 61 31 2d 34 31 63 61 2d 61 31 62 34 2d 35 34 31 31 34 36 65 34 63 31 36 66 } //1 6f2fa8b7-cca1-41ca-a1b4-541146e4c16f
		$a_03_2 = {20 80 f0 fa 02 6f ?? 00 00 0a } //1
		$a_81_3 = {47 65 74 54 65 6d 70 50 61 74 68 } //1 GetTempPath
		$a_81_4 = {6d 65 67 61 6c 69 6e 6b 62 6a } //1 megalinkbj
		$a_81_5 = {4f 61 6b 63 64 71 } //1 Oakcdq
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}