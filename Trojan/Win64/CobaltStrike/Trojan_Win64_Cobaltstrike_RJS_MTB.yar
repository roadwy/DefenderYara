
rule Trojan_Win64_Cobaltstrike_RJS_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.RJS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 b8 00 11 22 33 44 55 66 77 48 89 45 c8 48 b8 0f 05 90 90 c3 90 cc cc } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}