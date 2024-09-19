
rule Trojan_Win64_Cobaltstrike_PRD_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.PRD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {44 31 f0 42 88 44 3b 08 4c 89 f2 48 c1 fa 08 31 d0 4c 89 f2 48 c1 fa 10 31 d0 4c 89 f2 49 83 c6 01 48 c1 fa 18 31 d0 42 88 44 3b 08 49 83 c7 01 49 39 f7 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}