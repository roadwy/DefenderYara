
rule TrojanDownloader_BAT_AveMariaRAT_A_MTB{
	meta:
		description = "TrojanDownloader:BAT/AveMariaRAT.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {42 62 70 79 6b 7a 76 6d 73 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //2 Bbpykzvms.Properties.Resources.resources
		$a_01_1 = {6a 72 6d 36 63 63 6e 73 73 61 66 74 33 39 66 61 37 34 78 35 6a 74 75 65 32 72 6c 78 73 38 77 61 } //2 jrm6ccnssaft39fa74x5jtue2rlxs8wa
		$a_01_2 = {71 62 64 6e 70 79 64 6b 37 61 6e 38 6a 37 6d 6c 75 67 77 71 33 62 34 6b 6e 75 66 39 65 6b 6a 75 } //2 qbdnpydk7an8j7mlugwq3b4knuf9ekju
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}