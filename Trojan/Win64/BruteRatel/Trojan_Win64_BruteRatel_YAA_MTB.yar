
rule Trojan_Win64_BruteRatel_YAA_MTB{
	meta:
		description = "Trojan:Win64/BruteRatel.YAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {99 b9 2a 00 00 00 f7 f9 8b c2 48 98 48 8d 0d ?? ?? ?? ?? 0f be 04 01 8b 4c 24 74 33 c8 8b c1 89 84 24 a4 00 00 00 48 8d 0d 20 d6 04 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}