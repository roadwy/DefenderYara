
rule Trojan_Win64_Bumblebee_GB_MTB{
	meta:
		description = "Trojan:Win64/Bumblebee.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 8b 83 20 01 00 00 2b 41 20 05 d1 56 07 00 31 81 8c 00 00 00 49 81 fa d0 86 09 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}