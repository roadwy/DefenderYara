
rule Trojan_Win64_Cobaltstrike_WQF_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.WQF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 0f b6 04 24 0f b6 0a 48 83 c2 01 31 c8 49 83 c4 01 41 88 44 24 ff 4d 39 c4 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}