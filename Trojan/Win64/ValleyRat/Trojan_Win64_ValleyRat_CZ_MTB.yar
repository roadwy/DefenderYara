
rule Trojan_Win64_ValleyRat_CZ_MTB{
	meta:
		description = "Trojan:Win64/ValleyRat.CZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {49 8b c8 33 d2 49 8b c1 49 f7 70 10 8a 04 0a 43 30 04 19 49 ff c1 4d 3b ca 72 d9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}