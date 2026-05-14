
rule Trojan_Win64_Havoc_GTV_MTB{
	meta:
		description = "Trojan:Win64/Havoc.GTV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 fc 48 63 d0 48 8b 45 10 48 01 d0 0f b6 10 8b 45 fc 48 63 c8 48 8b 45 20 48 01 c8 83 f2 ab 88 10 83 45 fc 01 8b 45 fc 48 98 48 3b 45 18 } //5
		$a_01_1 = {29 c2 89 55 fc 8b 45 fc 05 2c 01 00 00 69 c0 e8 03 00 00 89 c1 48 8b 05 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}