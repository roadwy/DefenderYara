
rule Trojan_Win64_Amadey_CX_MTB{
	meta:
		description = "Trojan:Win64/Amadey.CX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {49 87 cf 49 89 c7 4c 87 f9 c6 04 10 90 01 01 80 34 10 90 01 01 80 2c 10 90 01 01 80 04 10 90 01 01 80 2c 10 90 01 01 48 d1 e1 48 c1 e1 90 01 01 48 d1 e1 48 90 01 06 48 03 c8 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}