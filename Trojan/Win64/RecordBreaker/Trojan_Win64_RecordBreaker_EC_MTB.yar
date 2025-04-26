
rule Trojan_Win64_RecordBreaker_EC_MTB{
	meta:
		description = "Trojan:Win64/RecordBreaker.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_01_0 = {31 c0 44 89 ca 41 33 14 80 88 14 01 48 ff c0 48 83 f8 0e 75 ed } //7
	condition:
		((#a_01_0  & 1)*7) >=7
 
}