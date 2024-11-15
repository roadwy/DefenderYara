
rule Trojan_Win64_BruteRatel_BKK_MTB{
	meta:
		description = "Trojan:Win64/BruteRatel.BKK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 0f b6 da 45 0f b6 d2 49 01 ca 45 0f b6 32 44 88 30 45 88 0a 44 02 08 45 0f b6 c9 42 0f b6 04 09 43 32 04 18 42 88 04 1a 4c 89 d8 49 83 c3 01 48 39 f8 75 b7 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}