
rule Trojan_Win64_PrivateLoader_NR_MTB{
	meta:
		description = "Trojan:Win64/PrivateLoader.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {80 00 09 48 ff c0 48 83 e9 90 01 01 75 f4 ff d3 48 8b 5c 24 90 01 01 33 c0 48 8b 7c 24 90 01 01 48 83 c4 50 90 00 } //05 00 
		$a_03_1 = {48 3b ca 74 1e 40 84 79 90 01 01 74 18 48 8b 40 90 01 01 eb 2b 05 ae dd ff ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}