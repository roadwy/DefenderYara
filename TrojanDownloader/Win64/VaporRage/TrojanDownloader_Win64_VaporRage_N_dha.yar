
rule TrojanDownloader_Win64_VaporRage_N_dha{
	meta:
		description = "TrojanDownloader:Win64/VaporRage.N!dha,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 01 00 00 "
		
	strings :
		$a_41_0 = {c0 49 89 c9 48 39 d0 74 19 48 89 c1 4d 89 c2 83 e1 07 48 c1 e1 03 49 d3 ea 45 30 14 01 48 ff c0 eb e2 c3 00 } //100
	condition:
		((#a_41_0  & 1)*100) >=100
 
}