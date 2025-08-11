
rule Trojan_Win64_Zusy_AUK_MTB{
	meta:
		description = "Trojan:Win64/Zusy.AUK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {4b 41 59 28 b5 2f fd 00 88 c4 cc 01 1a d4 5d 72 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}