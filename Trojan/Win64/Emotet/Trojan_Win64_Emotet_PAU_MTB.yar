
rule Trojan_Win64_Emotet_PAU_MTB{
	meta:
		description = "Trojan:Win64/Emotet.PAU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 e1 2b ca d1 e9 03 ca c1 e9 04 89 4c 24 90 01 01 81 44 24 90 02 06 81 74 24 90 02 06 c1 6c 24 90 02 06 81 74 24 90 02 06 c7 44 24 90 02 06 81 4c 24 90 02 06 81 74 24 90 02 06 c7 44 24 90 02 06 c1 6c 24 90 02 06 81 44 24 90 02 06 c1 6c 24 90 02 06 81 74 24 90 02 06 8b 44 24 90 01 01 8b 54 24 90 01 01 8b 4c 24 90 01 01 89 44 24 90 01 01 e8 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}