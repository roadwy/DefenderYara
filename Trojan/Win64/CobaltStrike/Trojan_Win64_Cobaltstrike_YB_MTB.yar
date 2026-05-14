
rule Trojan_Win64_Cobaltstrike_YB_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.YB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {80 34 19 ab 41 3b cf 72 f7 ff d3 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}