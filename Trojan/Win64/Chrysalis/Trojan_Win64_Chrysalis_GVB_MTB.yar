
rule Trojan_Win64_Chrysalis_GVB_MTB{
	meta:
		description = "Trojan:Win64/Chrysalis.GVB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f ba f8 0a 89 44 24 54 48 63 44 24 4c 0f b6 4c 24 54 88 8c 04 80 1c 00 00 8b 44 24 4c ff c0 89 44 24 4c 8b 44 24 50 83 c0 04 89 44 24 50 8b 44 24 44 83 c0 04 89 44 24 44 48 8d 4c 24 68 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}