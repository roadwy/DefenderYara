
rule Trojan_Win64_Tedy_ATY_MTB{
	meta:
		description = "Trojan:Win64/Tedy.ATY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {83 c8 05 88 43 40 48 85 d2 0f 84 54 01 00 00 48 83 7a 18 00 0f 84 39 01 00 00 48 8b 42 18 f0 83 00 01 48 8b 4b 30 48 85 c9 74 06 ff 15 c8 7d 01 00 4c 89 e9 e8 24 1d 00 00 48 8b 4b 28 ff 15 } //00 00 
	condition:
		any of ($a_*)
 
}