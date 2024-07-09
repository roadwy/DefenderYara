
rule Trojan_Win64_Amadey_CX_MTB{
	meta:
		description = "Trojan:Win64/Amadey.CX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {49 87 cf 49 89 c7 4c 87 f9 c6 04 10 ?? 80 34 10 ?? 80 2c 10 ?? 80 04 10 ?? 80 2c 10 ?? 48 d1 e1 48 c1 e1 ?? 48 d1 e1 48 ?? ?? ?? ?? ?? ?? 48 03 c8 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}