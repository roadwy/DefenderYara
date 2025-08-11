
rule Trojan_Win64_CobalStrike_ARAX_MTB{
	meta:
		description = "Trojan:Win64/CobalStrike.ARAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 32 ca 44 8b 54 24 30 41 ff c2 41 88 09 49 ff c1 44 89 54 24 30 4c 89 4c 24 28 41 8d 04 32 3b c3 0f 8c 79 fc ff ff } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}