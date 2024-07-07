
rule Trojan_Win64_Fabookie_CRQ_MTB{
	meta:
		description = "Trojan:Win64/Fabookie.CRQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 63 d0 4c 63 c0 4e 0f b6 04 01 41 80 f0 90 01 01 44 88 44 14 90 02 05 83 c0 01 83 f8 90 01 01 75 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}