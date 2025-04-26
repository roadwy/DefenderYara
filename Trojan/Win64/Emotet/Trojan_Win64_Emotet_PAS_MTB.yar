
rule Trojan_Win64_Emotet_PAS_MTB{
	meta:
		description = "Trojan:Win64/Emotet.PAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 d3 c1 fa 05 8b c2 c1 e8 1f 03 d0 6b d2 25 8b c3 2b c2 48 63 c8 48 8b [0-08] 0f b6 0c 01 32 0c 3e 88 0f } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}