
rule Trojan_Win64_Gozi_RF_MTB{
	meta:
		description = "Trojan:Win64/Gozi.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {66 89 11 48 83 c3 02 48 83 c1 02 66 41 3b d2 75 bb 49 3b fa 74 0a 48 2b c8 48 d1 f9 ff c9 89 0f } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}