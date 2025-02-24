
rule Trojan_Win64_NukeSped_DA_MTB{
	meta:
		description = "Trojan:Win64/NukeSped.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 43 01 ff ce 0f b6 0c 28 43 30 0c 26 41 ff c6 0f b6 43 01 fe c0 88 43 01 3c 40 75 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}