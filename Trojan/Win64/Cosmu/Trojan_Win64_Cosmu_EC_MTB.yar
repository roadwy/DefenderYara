
rule Trojan_Win64_Cosmu_EC_MTB{
	meta:
		description = "Trojan:Win64/Cosmu.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_01_0 = {a5 32 ab 32 a5 32 a6 32 97 32 9f 32 65 32 64 32 8e 32 9b 32 9f 32 93 32 99 32 97 32 a4 32 97 32 a5 32 60 32 } //7
	condition:
		((#a_01_0  & 1)*7) >=7
 
}