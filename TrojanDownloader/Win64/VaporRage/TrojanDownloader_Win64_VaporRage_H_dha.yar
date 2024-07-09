
rule TrojanDownloader_Win64_VaporRage_H_dha{
	meta:
		description = "TrojanDownloader:Win64/VaporRage.H!dha,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8b 45 10 49 b8 82 38 ba 4d f7 57 3c b8 ba ?? ?? ?? ?? 48 89 c1 e8 } //100
	condition:
		((#a_03_0  & 1)*100) >=100
 
}