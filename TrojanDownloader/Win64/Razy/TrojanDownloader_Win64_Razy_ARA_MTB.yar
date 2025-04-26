
rule TrojanDownloader_Win64_Razy_ARA_MTB{
	meta:
		description = "TrojanDownloader:Win64/Razy.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {30 30 31 2f 70 75 70 70 65 74 2e 54 78 74 } //2 001/puppet.Txt
		$a_01_1 = {2f 57 6f 77 4f 70 4f 2e 54 58 54 3f 25 64 } //2 /WowOpO.TXT?%d
		$a_01_2 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //2 DownloadFile
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}