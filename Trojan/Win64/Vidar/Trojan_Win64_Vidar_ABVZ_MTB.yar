
rule Trojan_Win64_Vidar_ABVZ_MTB{
	meta:
		description = "Trojan:Win64/Vidar.ABVZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 33 c0 48 8b 4c 24 38 01 19 48 8b 4c 24 58 48 8b 54 24 40 48 8d 0c 0a 48 8d 0c 19 48 8d 04 01 48 8b 4c 24 38 31 01 48 83 c3 04 48 8b 44 24 38 48 83 c0 04 48 89 44 24 38 48 8b 44 24 50 48 3b d8 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}