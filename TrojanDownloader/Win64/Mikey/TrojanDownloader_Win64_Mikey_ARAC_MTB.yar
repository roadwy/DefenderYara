
rule TrojanDownloader_Win64_Mikey_ARAC_MTB{
	meta:
		description = "TrojanDownloader:Win64/Mikey.ARAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 ff c7 f7 eb 8b c2 c1 e8 1f 03 d0 0f b6 c2 02 c0 02 d0 0f b6 c3 ff c3 2a c2 04 02 00 44 37 ff 49 3b f8 7c d6 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}