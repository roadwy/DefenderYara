
rule TrojanDownloader_Win32_VaporRage_G_dha{
	meta:
		description = "TrojanDownloader:Win32/VaporRage.G!dha,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 01 00 00 "
		
	strings :
		$a_41_0 = {0f b6 04 11 48 89 d0 83 e0 07 48 c1 e0 03 c4 c2 fb f7 c1 44 31 c0 88 04 11 48 ff c2 48 83 fa 1b 75 00 } //100
	condition:
		((#a_41_0  & 1)*100) >=100
 
}