
rule Trojan_Win64_IcedId_CAC_MTB{
	meta:
		description = "Trojan:Win64/IcedId.CAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {4b 8d 14 08 49 ff c0 8a 42 40 32 02 88 44 11 40 49 83 f8 20 72 ea } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}