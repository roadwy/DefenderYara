
rule Trojan_Win64_Latrodectus_PD_MTB{
	meta:
		description = "Trojan:Win64/Latrodectus.PD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 63 c8 49 8b c4 48 f7 e1 48 8b c1 48 2b c2 48 d1 e8 48 03 c2 48 c1 e8 04 48 6b c0 19 48 2b c8 49 2b cd 0f b6 44 0c 90 01 01 43 32 44 0a 90 01 01 41 88 41 90 01 01 41 8d 47 90 01 01 48 63 c8 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}