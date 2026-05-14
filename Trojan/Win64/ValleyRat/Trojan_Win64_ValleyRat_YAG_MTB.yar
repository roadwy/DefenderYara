
rule Trojan_Win64_ValleyRat_YAG_MTB{
	meta:
		description = "Trojan:Win64/ValleyRat.YAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 44 24 30 8b 0c 24 48 8b 54 24 20 0f b6 0c 0a 33 c8 8b c1 8b 0c 24 48 8b 54 24 20 88 04 0a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}