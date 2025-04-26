
rule TrojanSpy_BAT_Stealergen_MT_MTB{
	meta:
		description = "TrojanSpy:BAT/Stealergen.MT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {74 69 6d 65 72 53 70 6c 61 73 68 5f 54 69 63 6b } //1 timerSplash_Tick
		$a_01_1 = {58 6f 79 46 61 72 6d 6f 73 68 4b 52 44 61 61 } //1 XoyFarmoshKRDaa
		$a_01_2 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
		$a_01_3 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 73 00 70 00 61 00 63 00 65 00 63 00 6f 00 69 00 6e 00 2e 00 63 00 63 00 } //1 https://spacecoin.cc
		$a_01_4 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_01_5 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_01_6 = {54 6f 53 74 72 69 6e 67 } //1 ToString
		$a_01_7 = {72 61 64 50 61 79 44 65 62 69 74 } //1 radPayDebit
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}