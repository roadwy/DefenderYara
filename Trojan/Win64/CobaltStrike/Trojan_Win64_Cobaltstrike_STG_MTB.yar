
rule Trojan_Win64_Cobaltstrike_STG_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.STG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 89 f8 40 c0 ef 04 40 0f b6 ff 4c 8d 0d c5 c2 03 00 42 0f b6 3c 0f 48 83 fe 04 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}