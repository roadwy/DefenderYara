
rule Trojan_Win64_Cobalt_AMAB_MTB{
	meta:
		description = "Trojan:Win64/Cobalt.AMAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 04 24 ff c0 89 04 24 83 3c 24 21 7d ?? 48 63 04 24 48 8b 4c 24 28 0f be 04 01 89 44 24 04 8b 04 24 99 b9 ?? ?? ?? ?? f7 f9 8b c2 83 c0 32 8b 4c 24 04 33 c8 8b c1 48 63 0c 24 48 8b 54 24 20 88 04 0a eb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}