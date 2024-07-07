
rule Trojan_Win64_QakbotPacker_QM_MTB{
	meta:
		description = "Trojan:Win64/QakbotPacker.QM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {f5 d7 39 07 d7 e7 90 01 01 03 35 90 01 04 98 35 90 01 04 e0 90 01 01 ff 07 d7 4a 33 98 90 01 04 6a 90 01 01 75 90 01 01 f5 1a d7 e4 90 01 01 6a 0f 75 90 01 01 f5 2b 73 90 01 01 f5 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}