
rule Trojan_Win64_Cobaltstrike_ROX_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.ROX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 0a 41 88 0c 28 44 88 0a 41 0f b6 14 28 49 03 d1 0f b6 ca 0f b6 94 0c 50 04 00 00 41 30 12 49 ff c2 49 83 eb 01 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}