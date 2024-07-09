
rule Trojan_Win64_Mozaakai_CE_MTB{
	meta:
		description = "Trojan:Win64/Mozaakai.CE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 d2 41 8d 43 [0-01] f7 f1 48 83 c3 [0-01] 4c 63 da 33 d2 47 0f b6 04 13 42 8d 04 06 f7 f1 48 63 f2 33 d2 42 0f b6 04 16 43 88 04 13 46 88 04 16 43 0f b6 04 13 41 03 c0 f7 35 [0-04] 48 63 c2 42 0f b6 0c 10 30 4b ff 48 83 ef [0-01] 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}