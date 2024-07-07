
rule TrojanDownloader_AndroidOS_SAgent_A_MTB{
	meta:
		description = "TrojanDownloader:AndroidOS/SAgent.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {61 70 69 2e 6e 66 6a 6d 66 73 2e 78 79 7a } //1 api.nfjmfs.xyz
		$a_00_1 = {63 68 61 6f 64 61 69 67 61 6e 2e 63 6f 6d } //1 chaodaigan.com
		$a_00_2 = {6a 69 6e 67 6f 6e 67 79 69 6e 6a 69 61 6e 67 2e 63 6f 6d } //1 jingongyinjiang.com
		$a_01_3 = {4b 65 66 75 57 65 62 56 69 65 77 41 63 74 69 76 69 74 79 } //1 KefuWebViewActivity
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}