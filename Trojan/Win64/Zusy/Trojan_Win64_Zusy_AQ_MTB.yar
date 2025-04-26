
rule Trojan_Win64_Zusy_AQ_MTB{
	meta:
		description = "Trojan:Win64/Zusy.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b7 ce ff 15 ?? ?? 00 00 66 89 44 24 2a 48 8d 46 01 0f b7 f0 41 b8 10 00 00 00 48 8d 54 24 28 48 8b cd ff 15 ?? ?? 00 00 48 8b 47 10 33 db 48 8b 08 48 85 c9 74 } //5
		$a_03_1 = {0f b7 09 ff 15 ?? ?? 00 00 48 8b 0f 66 89 44 24 ?? 48 8b 09 ff 15 ?? ?? 00 00 89 44 24 ?? 44 8d 43 0f 33 c0 8b d3 8b cb 48 89 44 24 ?? ff 15 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=5
 
}