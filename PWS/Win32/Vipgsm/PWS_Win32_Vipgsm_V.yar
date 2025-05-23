
rule PWS_Win32_Vipgsm_V{
	meta:
		description = "PWS:Win32/Vipgsm.V,SIGNATURE_TYPE_PEHSTR,12 00 12 00 12 00 00 "
		
	strings :
		$a_01_0 = {6b 61 73 70 65 72 73 6b 79 2d 6c 61 62 73 } //1 kaspersky-labs
		$a_01_1 = {76 69 72 75 73 6c 69 73 74 } //1 viruslist
		$a_01_2 = {73 79 6d 61 74 65 63 } //1 symatec
		$a_01_3 = {75 70 64 61 74 65 2e 73 79 6d 61 6e 74 65 63 } //1 update.symantec
		$a_01_4 = {73 79 6d 61 6e 74 65 63 6c 69 76 65 75 70 64 61 74 65 } //1 symantecliveupdate
		$a_01_5 = {73 6f 70 68 6f 73 } //1 sophos
		$a_01_6 = {6e 6f 72 74 6f 6e } //1 norton
		$a_01_7 = {6d 63 61 66 65 65 } //1 mcafee
		$a_01_8 = {6c 69 76 65 75 70 64 61 74 65 2e 73 79 6d 61 6e 74 65 63 6c 69 76 65 75 70 64 61 74 65 } //1 liveupdate.symantecliveupdate
		$a_01_9 = {66 2d 73 65 63 75 72 65 } //1 f-secure
		$a_01_10 = {73 65 63 75 72 65 2e 6e 61 69 } //1 secure.nai
		$a_01_11 = {6d 79 2d 65 74 72 75 73 74 } //1 my-etrust
		$a_01_12 = {6e 65 74 77 6f 72 6b 61 73 73 6f 63 69 61 74 65 73 } //1 networkassociates
		$a_01_13 = {74 72 65 6e 64 6d 69 63 72 6f } //1 trendmicro
		$a_01_14 = {67 72 69 73 6f 66 74 } //1 grisoft
		$a_01_15 = {73 61 6e 64 62 6f 78 2e 6e 6f 72 6d 61 6e } //1 sandbox.norman
		$a_01_16 = {75 6b 2e 74 72 65 6e 64 6d 69 63 72 6f 2d 65 75 72 6f 70 65 } //1 uk.trendmicro-europe
		$a_01_17 = {54 63 70 43 68 65 63 6b 49 6e 69 74 } //1 TcpCheckInit
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1+(#a_01_16  & 1)*1+(#a_01_17  & 1)*1) >=18
 
}