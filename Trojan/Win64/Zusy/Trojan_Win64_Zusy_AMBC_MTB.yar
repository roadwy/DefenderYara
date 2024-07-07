
rule Trojan_Win64_Zusy_AMBC_MTB{
	meta:
		description = "Trojan:Win64/Zusy.AMBC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 41 58 30 44 0d a8 48 ff c1 48 83 f9 90 01 01 72 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}