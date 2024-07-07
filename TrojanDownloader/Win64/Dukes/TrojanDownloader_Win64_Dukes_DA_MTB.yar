
rule TrojanDownloader_Win64_Dukes_DA_MTB{
	meta:
		description = "TrojanDownloader:Win64/Dukes.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {49 8b 45 08 48 83 e8 10 48 39 c8 76 90 01 01 48 89 c8 31 d2 4c 8b 4c 24 50 48 f7 74 24 58 49 8b 45 00 41 8a 14 11 32 54 08 10 89 c8 41 0f af c0 31 c2 88 14 0b 48 ff c1 eb 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}