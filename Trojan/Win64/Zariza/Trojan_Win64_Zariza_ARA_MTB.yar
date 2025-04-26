
rule Trojan_Win64_Zariza_ARA_MTB{
	meta:
		description = "Trojan:Win64/Zariza.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8b 00 49 8b 4c 24 e8 8a 04 01 44 28 f0 48 8b 4c 24 30 42 88 04 31 49 ff c6 e9 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}