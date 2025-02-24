
rule Trojan_Win64_Cobaltstrike_KAU_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.KAU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 89 44 24 20 48 8d 44 24 30 48 8b 7c 24 20 48 8b f0 b9 07 16 05 00 f3 a4 4c 8d 4c 24 28 41 b8 20 00 00 00 ba 07 16 05 00 48 8b 4c 24 20 ff ?? ?? ?? ?? ?? ff 54 24 20 48 8b 8c 24 40 16 05 00 48 33 cc } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}