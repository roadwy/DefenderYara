
rule TrojanDownloader_Win64_DuckTail_A_MTB{
	meta:
		description = "TrojanDownloader:Win64/DuckTail.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {44 0f be c0 48 8b 44 ?? ?? 48 8b 0c ?? 0f be 14 08 44 31 c2 88 14 08 48 8b 04 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}