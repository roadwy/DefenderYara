
rule TrojanSpy_AndroidOS_Goodnews_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Goodnews.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {70 6c 65 61 73 65 20 6d 61 6b 65 20 73 75 72 65 20 69 74 20 69 73 20 69 6e 20 74 68 65 20 66 6f 72 6d 61 74 20 6f 66 } //1 please make sure it is in the format of
		$a_00_1 = {55 6e 61 62 6c 65 20 74 6f 20 73 65 74 20 74 65 73 74 20 64 65 76 69 63 65 20 61 64 76 65 72 74 69 73 69 6e 67 20 69 64 } //1 Unable to set test device advertising id
		$a_00_2 = {54 6f 20 41 63 74 69 76 61 74 65 20 79 6f 75 72 20 54 69 6b 74 6f 6b 20 70 6c 65 61 73 65 20 66 6f 6c 6c 6f 77 20 6e 65 78 74 20 69 6e 73 74 72 75 63 74 69 6f 6e } //1 To Activate your Tiktok please follow next instruction
		$a_00_3 = {57 61 74 63 68 20 66 75 6c 6c 20 56 69 64 65 6f 20 74 6f 20 67 65 74 20 4f 66 66 65 72 } //1 Watch full Video to get Offer
		$a_00_4 = {6d 65 64 69 61 74 69 6f 6e 5f 74 69 6b 74 6f 6b 5f 6e 65 74 77 6f 72 6b } //1 mediation_tiktok_network
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}