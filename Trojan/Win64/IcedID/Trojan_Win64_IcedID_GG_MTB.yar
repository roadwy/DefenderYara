
rule Trojan_Win64_IcedID_GG_MTB{
	meta:
		description = "Trojan:Win64/IcedID.GG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {44 89 4c 24 20 4c 89 44 24 18 66 3b c0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}