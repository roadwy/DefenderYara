
rule Trojan_Win64_Emotet_PBD_MTB{
	meta:
		description = "Trojan:Win64/Emotet.PBD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {49 8b ca 49 83 c1 90 01 01 49 83 c2 90 01 01 41 f7 e0 41 8b c0 41 83 c0 90 01 01 2b c2 d1 90 01 01 03 c2 c1 e8 90 01 01 48 6b c0 90 01 01 48 2b c8 0f b6 04 19 42 32 44 0e 90 01 01 44 3b c5 41 88 41 90 01 01 72 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}