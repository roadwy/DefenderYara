
rule Trojan_Win64_Latrodectus_PA_MTB{
	meta:
		description = "Trojan:Win64/Latrodectus.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c1 99 8b 8c 24 90 01 04 f7 f9 48 98 48 8d 44 04 90 01 01 48 8b 8c 24 90 01 04 0f b6 04 08 8b 8c 24 90 01 04 33 c8 8b c1 48 63 4c 24 90 01 01 48 8b 54 24 90 01 01 88 04 0a e9 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}