
rule Trojan_Win64_Cobaltstrike_DN_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.DN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 63 c2 48 8d 4d c0 48 03 c8 0f b6 01 41 88 04 38 44 88 09 41 0f b6 04 38 41 03 c1 0f b6 c0 0f b6 4c 05 c0 41 30 0a 49 ff c2 49 83 ee 01 75 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}