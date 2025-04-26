
rule Trojan_Win64_Cobaltstrike_ALJ_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.ALJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 8a 04 04 30 04 33 48 ff c6 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}