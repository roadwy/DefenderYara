
rule TrojanDownloader_Win64_Mikey_ARA_MTB{
	meta:
		description = "TrojanDownloader:Win64/Mikey.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c8 ff ff c1 48 8d 52 01 2a 42 ff 88 42 ff 48 63 c1 48 83 f8 ?? 72 e8 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}