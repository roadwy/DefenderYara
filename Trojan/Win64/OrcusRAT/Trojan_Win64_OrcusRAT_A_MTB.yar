
rule Trojan_Win64_OrcusRAT_A_MTB{
	meta:
		description = "Trojan:Win64/OrcusRAT.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8d 41 f1 30 04 39 48 ff c1 48 81 f9 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}