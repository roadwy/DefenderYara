
rule Trojan_Win64_IcedID_EX_MTB{
	meta:
		description = "Trojan:Win64/IcedID.EX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b6 4c 0c 50 33 c1 3a ff } //1
		$a_01_1 = {48 63 44 24 2c 0f b6 44 04 50 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}