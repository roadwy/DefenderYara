
rule Trojan_Win64_Loader_EC_MTB{
	meta:
		description = "Trojan:Win64/Loader.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 8b cc 8a 45 c0 30 44 0d c1 48 ff c1 48 83 f9 14 72 f0 44 88 65 d5 0f 57 c0 } //3
	condition:
		((#a_01_0  & 1)*3) >=3
 
}