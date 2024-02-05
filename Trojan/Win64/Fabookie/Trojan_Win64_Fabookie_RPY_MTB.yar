
rule Trojan_Win64_Fabookie_RPY_MTB{
	meta:
		description = "Trojan:Win64/Fabookie.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 8b f0 8b 08 83 e1 3f 80 f9 09 0f 85 6e 01 00 00 48 8d 48 08 48 85 c9 0f 84 7f 01 00 00 80 39 01 0f 85 76 01 00 00 0f b6 69 09 0f b6 41 0a 80 00 0d 48 ff c0 eb 69 } //00 00 
	condition:
		any of ($a_*)
 
}