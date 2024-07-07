
rule Trojan_Win64_Ceilscour_YAB_MTB{
	meta:
		description = "Trojan:Win64/Ceilscour.YAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {44 0f b6 07 48 63 ca 41 80 f0 08 48 03 ce 74 56 49 3b ca 73 22 66 66 66 90 01 04 00 00 00 00 0f b6 c1 40 2a c6 24 08 32 01 41 32 c0 88 01 49 03 cb 49 3b ca 72 e9 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}