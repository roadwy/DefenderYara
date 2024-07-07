
rule Trojan_Win64_Implant_A_MTB{
	meta:
		description = "Trojan:Win64/Implant.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {4c 8b 44 24 90 01 01 48 8d 44 24 90 01 01 48 8b 4c 24 90 01 01 45 33 c9 ba 10 66 00 00 48 89 44 24 90 00 } //2
		$a_03_1 = {48 8b 4c 24 90 01 01 48 8d 84 24 90 01 04 48 89 44 24 90 01 01 45 33 c9 48 8b 84 24 90 01 04 45 33 c0 33 d2 48 89 44 24 90 00 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}