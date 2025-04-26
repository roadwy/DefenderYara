
rule Trojan_Win64_Baryas_MBXY_MTB{
	meta:
		description = "Trojan:Win64/Baryas.MBXY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {44 6c 6c 4c 6f 61 64 00 44 6c 6c 4c 6f 61 64 58 00 50 32 50 4d 61 69 6e 53 74 61 72 74 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}