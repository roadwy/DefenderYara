
rule Trojan_Win64_Cobaltstrike_AMMC_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.AMMC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 89 c2 83 e2 ?? 8a 54 15 ?? 32 14 07 88 14 01 48 ff c0 eb } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}