
rule TrojanDownloader_Win64_Carberp_A_bit{
	meta:
		description = "TrojanDownloader:Win64/Carberp.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {45 33 db 4c 8b c9 45 8b c3 45 8a d3 66 44 39 19 74 1f 41 0f b6 11 4d 8d 49 02 44 32 d2 44 33 c2 41 80 e2 1f 41 0f b6 ca 41 d3 c0 66 45 39 19 75 e1 } //1
		$a_01_1 = {76 6e 63 64 6c 6c 36 34 2e 64 6c 6c 00 56 6e 63 53 74 61 72 74 53 65 72 76 65 72 00 56 6e 63 53 74 6f 70 53 65 72 76 65 72 00 } //1 湶摣汬㐶搮汬嘀据瑓牡却牥敶r湖卣潴印牥敶r
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}