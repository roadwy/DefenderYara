
rule Trojan_Win64_Lazy_AE_MTB{
	meta:
		description = "Trojan:Win64/Lazy.AE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {49 8d 04 2c 48 8b 50 08 4c 8b 18 4c 31 ca 4d 31 d3 4c 09 da 0f 85 } //01 00 
		$a_01_1 = {4a 00 50 01 4a 00 e8 54 4d 00 28 f8 18 00 } //00 00 
	condition:
		any of ($a_*)
 
}