
rule Trojan_Win64_IcedID_PACY_MTB{
	meta:
		description = "Trojan:Win64/IcedID.PACY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 11 88 54 24 21 80 44 24 21 cc c0 64 24 21 04 8a 54 24 21 88 54 24 22 8a 51 01 88 54 24 21 80 44 24 21 c9 8a 54 24 21 08 54 24 22 8a 54 24 23 30 54 24 22 fe 44 24 23 8a 54 24 22 88 10 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}