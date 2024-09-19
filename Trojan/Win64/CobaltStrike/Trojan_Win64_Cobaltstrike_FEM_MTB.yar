
rule Trojan_Win64_Cobaltstrike_FEM_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.FEM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b c8 c1 e9 1e 33 c1 69 c0 65 89 07 6c 41 03 c0 89 44 94 64 41 ff c0 48 ff c2 49 3b d1 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}