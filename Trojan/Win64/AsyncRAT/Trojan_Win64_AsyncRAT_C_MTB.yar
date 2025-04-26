
rule Trojan_Win64_AsyncRAT_C_MTB{
	meta:
		description = "Trojan:Win64/AsyncRAT.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {45 30 04 03 48 ff c0 48 39 c7 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}