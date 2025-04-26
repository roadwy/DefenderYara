
rule Trojan_Win64_Cobaltstrike_NSK_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.NSK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 89 c1 4c 89 c2 83 e1 07 48 c1 e1 03 48 d3 ea 41 30 54 05 00 48 83 c0 01 48 83 f8 32 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}