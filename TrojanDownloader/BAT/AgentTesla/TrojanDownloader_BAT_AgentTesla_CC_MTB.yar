
rule TrojanDownloader_BAT_AgentTesla_CC_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.CC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {69 00 70 00 6c 00 6f 00 67 00 67 00 65 00 72 00 2e 00 6f 00 72 00 67 00 2f 00 31 00 78 00 65 00 32 00 78 00 37 00 } //1 iplogger.org/1xe2x7
		$a_01_1 = {66 00 30 00 35 00 30 00 38 00 35 00 36 00 34 00 2e 00 78 00 73 00 70 00 68 00 2e 00 72 00 75 00 2f 00 6c 00 69 00 62 00 58 00 4f 00 52 00 2e 00 66 00 67 00 72 00 65 00 64 00 66 00 73 00 } //1 f0508564.xsph.ru/libXOR.fgredfs
		$a_01_2 = {61 00 30 00 36 00 34 00 31 00 37 00 32 00 39 00 2e 00 78 00 73 00 70 00 68 00 2e 00 72 00 75 00 2f 00 6a 00 69 00 72 00 6d 00 7a 00 72 00 57 00 4d 00 31 00 2e 00 65 00 78 00 65 00 } //1 a0641729.xsph.ru/jirmzrWM1.exe
		$a_01_3 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}