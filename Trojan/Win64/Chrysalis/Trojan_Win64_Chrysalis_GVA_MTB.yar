
rule Trojan_Win64_Chrysalis_GVA_MTB{
	meta:
		description = "Trojan:Win64/Chrysalis.GVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {2d 00 04 00 00 35 00 04 00 00 89 85 5c 37 00 00 8b 85 5c 37 00 00 48 8b 8d 60 37 00 00 8b 11 41 89 d0 41 83 c0 01 44 89 01 89 d1 88 44 0d c0 8b 85 7c 37 00 00 83 c0 04 89 85 7c 37 00 00 8b 85 78 37 00 00 83 c0 04 89 85 78 37 00 00 8b 85 7c 37 00 00 89 85 74 37 00 00 c7 85 6c 37 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}