
rule Trojan_Win64_Emotet_PAG_MTB{
	meta:
		description = "Trojan:Win64/Emotet.PAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 fa 04 8b c2 c1 e8 1f 03 d0 41 8b c3 41 83 c3 03 6b d2 90 01 01 2b c2 83 c0 02 48 63 c8 48 8b 90 02 06 0f b6 0c 01 42 32 4c 16 90 01 01 41 88 4a 90 01 01 49 ff ce 74 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}