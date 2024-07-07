
rule TrojanDownloader_O97M_Emotet_QWSM_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.QWSM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_01_0 = {77 77 77 2e 73 75 64 64 65 64 78 2e 63 6f 6d 2f 6a 6f 6b 65 72 73 6c 6f 74 2f 6d 62 32 45 61 64 62 64 73 73 68 2f } //1 www.suddedx.com/jokerslot/mb2Eadbdssh/
		$a_01_1 = {66 79 61 6d 62 65 2e 6e 65 77 73 2f 63 67 69 2d 62 69 6e 2f 57 62 65 34 30 74 66 79 6e 46 73 34 72 43 2f } //1 fyambe.news/cgi-bin/Wbe40tfynFs4rC/
		$a_01_2 = {74 61 73 73 69 72 61 2e 63 6f 6d 2f 57 6f 72 64 50 72 65 73 73 2f 76 77 5a 51 4c 34 5a 35 42 50 63 46 4c 33 7a 2f } //1 tassira.com/WordPress/vwZQL4Z5BPcFL3z/
		$a_01_3 = {68 61 74 68 61 61 62 65 61 63 68 2e 63 6f 6d 2f 64 6f 63 75 6d 65 6e 74 73 2f 70 72 36 2f } //1 hathaabeach.com/documents/pr6/
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=1
 
}