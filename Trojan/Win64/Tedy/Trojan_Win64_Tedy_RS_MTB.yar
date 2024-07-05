
rule Trojan_Win64_Tedy_RS_MTB{
	meta:
		description = "Trojan:Win64/Tedy.RS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 8b 84 24 00 01 00 00 48 63 40 3c 48 8b 4c 24 48 48 03 c8 48 8b c1 48 63 4c 24 6c 48 6b c9 28 48 8d 84 08 08 01 00 00 48 89 84 24 98 00 00 00 48 8b 84 24 98 00 00 00 8b 40 14 48 8b 8c 24 98 00 00 00 8b 49 10 48 03 c1 48 89 84 24 c8 01 00 00 eb } //00 00 
	condition:
		any of ($a_*)
 
}