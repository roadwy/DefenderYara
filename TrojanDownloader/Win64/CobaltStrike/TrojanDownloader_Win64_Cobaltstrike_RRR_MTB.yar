
rule TrojanDownloader_Win64_Cobaltstrike_RRR_MTB{
	meta:
		description = "TrojanDownloader:Win64/Cobaltstrike.RRR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {74 70 3a 2f 2f 34 37 2e 31 30 39 2e 31 35 39 2e 32 35 3a 37 30 38 30 2f 32 39 35 32 34 2e 74 78 74 } //1 tp://47.109.159.25:7080/29524.txt
		$a_01_1 = {48 8d 1d c9 e7 07 00 b9 23 00 00 00 e8 5a c0 fa ff 48 85 db } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}