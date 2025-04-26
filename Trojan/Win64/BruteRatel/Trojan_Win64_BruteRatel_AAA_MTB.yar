
rule Trojan_Win64_BruteRatel_AAA_MTB{
	meta:
		description = "Trojan:Win64/BruteRatel.AAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {49 f7 e0 48 c1 ea 02 48 8d 04 92 48 8d 04 42 48 01 c0 48 29 c7 0f b6 44 3c ?? 42 32 04 09 48 8b 54 24 ?? 88 04 0a 48 83 c1 01 48 39 4c 24 ?? 77 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}