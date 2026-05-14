
rule Trojan_Win64_Formbook_PGFB_MTB{
	meta:
		description = "Trojan:Win64/Formbook.PGFB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {83 ea 01 72 2a 49 01 ed 48 c1 c5 1f 4c 31 ed 4d 01 c4 49 c1 c0 1d 4d 31 e0 4d 01 c5 49 c1 c0 17 4d 31 e8 49 01 ec 48 c1 c5 11 4c 31 e5 eb d1 } //5
		$a_01_1 = {48 39 d7 74 14 4c 8b 06 4d 01 d8 44 8a 4c 14 30 46 30 0c 02 48 ff c2 eb e7 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}