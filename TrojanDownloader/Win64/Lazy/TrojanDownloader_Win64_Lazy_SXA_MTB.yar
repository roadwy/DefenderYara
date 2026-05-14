
rule TrojanDownloader_Win64_Lazy_SXA_MTB{
	meta:
		description = "TrojanDownloader:Win64/Lazy.SXA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 02 00 00 "
		
	strings :
		$a_03_0 = {f3 41 0f 6f 00 66 0f 6f ca 0f 57 c8 f3 41 0f 7f 08 f3 41 0f 6f 40 ?? 66 0f 6f ca 0f 57 c8 f3 41 0f 7f 48 ?? f3 41 0f 6f 40 ?? 66 0f 6f ca 0f 57 c8 f3 41 0f 7f 48 ?? f3 41 0f 6f 40 ?? 66 0f 6f ca 0f 57 c8 f3 41 0f 7f 48 ?? 49 83 c0 40 48 83 c2 40 48 3b d1 } //20
		$a_80_1 = {5c 53 63 72 65 65 6e 73 68 6f 74 20 61 6c 62 75 6d } //\Screenshot album  5
	condition:
		((#a_03_0  & 1)*20+(#a_80_1  & 1)*5) >=25
 
}