
rule TrojanDownloader_BAT_AgentTesla_NLR_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.NLR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {6b 6f 74 61 64 69 61 69 6e 63 2e 63 6f 6d 2f 4a 72 69 77 77 2e 70 6e 67 } //kotadiainc.com/Jriww.png  1
		$a_01_1 = {52 65 76 65 72 73 65 72 44 61 74 61 } //1 ReverserData
		$a_01_2 = {2f 00 63 00 20 00 74 00 69 00 6d 00 65 00 6f 00 75 00 74 00 20 00 32 00 30 } //1
		$a_01_3 = {52 00 65 00 76 00 65 00 72 00 73 00 65 00 00 07 63 00 6d 00 64 } //1
		$a_01_4 = {44 00 78 00 79 00 72 00 6d 00 63 00 68 00 62 00 71 00 76 00 6a 00 71 00 76 00 6b 00 72 00 6c 00 66 00 68 00 61 00 75 00 6e 00 67 00 61 00 7a } //1
	condition:
		((#a_80_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}