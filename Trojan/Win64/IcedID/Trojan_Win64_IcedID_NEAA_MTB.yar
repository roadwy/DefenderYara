
rule Trojan_Win64_IcedID_NEAA_MTB{
	meta:
		description = "Trojan:Win64/IcedID.NEAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {45 01 e3 41 29 cb 44 01 d8 48 98 8a 04 02 42 32 44 15 00 43 88 44 15 00 49 ff c2 e9 24 ff ff ff } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}