
rule Trojan_Win64_Zusy_EC_MTB{
	meta:
		description = "Trojan:Win64/Zusy.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 89 d0 48 c1 e8 02 48 31 d0 48 89 c2 48 c1 ea 15 48 31 c2 48 89 d0 48 c1 e8 16 48 31 d0 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}