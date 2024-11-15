
rule Trojan_Win64_BruteRatel_CMZ_MTB{
	meta:
		description = "Trojan:Win64/BruteRatel.CMZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 89 c8 49 f7 e1 48 c1 ea 04 48 8d 04 d2 48 8d 04 42 48 89 ce 48 29 c6 0f b6 84 34 ?? ?? ?? ?? 42 32 04 01 48 8b 94 24 ?? ?? ?? ?? 88 04 0a 48 83 c1 01 48 39 8c 24 ?? ?? ?? ?? 77 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}