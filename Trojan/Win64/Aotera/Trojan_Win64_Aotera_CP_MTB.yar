
rule Trojan_Win64_Aotera_CP_MTB{
	meta:
		description = "Trojan:Win64/Aotera.CP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 54 05 00 30 14 03 48 83 c0 01 4c 39 f8 72 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}