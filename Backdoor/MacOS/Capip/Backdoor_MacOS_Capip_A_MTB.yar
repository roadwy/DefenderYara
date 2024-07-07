
rule Backdoor_MacOS_Capip_A_MTB{
	meta:
		description = "Backdoor:MacOS/Capip.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_02_0 = {61 70 69 2e 90 02 20 2e 63 6f 6d 2f 67 75 61 72 64 69 61 6e 90 00 } //1
		$a_00_1 = {52 65 6d 6f 74 65 20 73 63 72 69 70 74 3a } //1 Remote script:
		$a_00_2 = {57 41 52 4e 49 4e 47 3a 20 42 6f 64 79 20 69 73 20 6e 6f 74 20 65 6d 70 74 79 20 65 76 65 6e 20 74 68 6f 75 67 68 20 72 65 71 75 65 73 74 20 69 73 20 6e 6f 74 20 50 4f 53 54 20 6f 72 20 50 55 54 2e 20 49 73 20 74 68 69 73 20 61 20 6d 69 73 74 61 6b 65 } //1 WARNING: Body is not empty even though request is not POST or PUT. Is this a mistake
		$a_00_3 = {73 38 67 75 61 72 64 69 61 6e 31 31 73 65 6e 64 52 65 71 75 65 73 74 33 75 72 6c 36 6d 65 74 68 6f 64 34 62 6f 64 79 31 30 46 6f 75 6e 64 61 74 69 6f 6e 34 44 61 74 61 56 53 53 } //1 s8guardian11sendRequest3url6method4body10Foundation4DataVSS
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}