
rule TrojanDownloader_BAT_ZgRAT_C_MTB{
	meta:
		description = "TrojanDownloader:BAT/ZgRAT.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 08 06 91 11 ?? 06 11 ?? 6f ?? ?? 00 0a 5d 6f ?? ?? 00 0a 61 d2 9c 06 17 58 0a 06 08 8e 69 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}