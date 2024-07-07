
rule TrojanDownloader_BAT_AgentTesla_RDJ_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.RDJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {11 04 11 05 09 11 05 09 8e 69 5d 91 08 11 05 91 61 d2 6f 90 01 04 11 05 17 58 13 05 11 05 08 8e 69 90 00 } //2
		$a_01_1 = {64 35 32 37 34 66 36 30 2d 33 33 38 37 2d 34 33 39 38 2d 61 33 36 33 2d 35 65 35 39 64 34 35 32 34 66 61 30 } //1 d5274f60-3387-4398-a363-5e59d4524fa0
		$a_01_2 = {45 00 69 00 6d 00 75 00 79 00 72 00 73 00 2e 00 4b 00 76 00 66 00 67 00 64 00 6a 00 6c 00 65 00 76 00 67 00 75 00 6a 00 6a 00 64 00 76 00 68 00 6e 00 65 00 75 00 68 00 } //1 Eimuyrs.Kvfgdjlevgujjdvhneuh
		$a_01_3 = {41 00 66 00 76 00 6b 00 67 00 6c 00 72 00 78 00 62 00 6d 00 63 00 71 00 74 00 73 00 72 00 67 00 68 00 64 00 71 00 75 00 62 00 6d 00 67 00 78 00 } //1 Afvkglrxbmcqtsrghdqubmgx
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}