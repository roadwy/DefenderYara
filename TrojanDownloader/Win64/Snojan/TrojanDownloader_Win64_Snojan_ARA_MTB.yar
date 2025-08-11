
rule TrojanDownloader_Win64_Snojan_ARA_MTB{
	meta:
		description = "TrojanDownloader:Win64/Snojan.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8d 48 13 30 4c 14 48 ff c0 48 63 d0 48 83 fa 0d 72 ee } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}