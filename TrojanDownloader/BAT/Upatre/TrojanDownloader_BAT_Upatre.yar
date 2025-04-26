
rule TrojanDownloader_BAT_Upatre{
	meta:
		description = "TrojanDownloader:BAT/Upatre,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {6f 1f 00 00 0a ?? 6f 20 00 00 0a d8 19 d8 17 da 17 d6 8d 18 00 00 01 } //1
		$a_03_1 = {b7 17 da 11 04 da 02 11 04 91 ?? 61 ?? 11 04 ?? 8e b7 5d 91 61 9c 11 04 17 d6 13 04 11 04 11 05 31 db ?? 2a } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}