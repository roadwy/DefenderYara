
rule Trojan_Win64_IcedID_FK_MTB{
	meta:
		description = "Trojan:Win64/IcedID.FK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {49 63 c9 48 b8 90 01 08 45 03 cc 48 f7 e1 48 c1 ea 90 01 01 48 8d 04 d2 48 03 c0 48 2b c8 48 2b cb 8a 44 0c 90 01 01 43 32 04 13 41 88 02 4d 03 d4 45 3b cd 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win64_IcedID_FK_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.FK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {8a 44 94 40 42 02 44 84 90 01 01 43 32 04 33 42 8b 4c 84 90 01 01 41 88 04 1b 83 e1 07 8b 44 94 90 01 01 49 ff c3 d3 c8 ff c0 89 44 94 40 8b c8 42 8b 44 84 90 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}