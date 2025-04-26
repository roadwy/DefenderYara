
rule Trojan_Win64_Emotet_JD_MTB{
	meta:
		description = "Trojan:Win64/Emotet.JD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b c2 d1 e8 03 c2 8b d1 c1 e8 ?? ff c1 6b c0 ?? 2b d0 43 8d 04 0e 4c 63 c2 48 63 d0 49 63 c1 47 0f b6 04 18 44 32 04 2a 44 88 04 38 3b ce } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}