
rule Trojan_Win64_Emotet_DJ_MTB{
	meta:
		description = "Trojan:Win64/Emotet.DJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {f7 f9 8b c2 48 98 48 8b 4c 24 20 0f b6 04 01 8b 4c 24 38 33 c8 8b c1 48 63 4c 24 30 48 8b 54 24 28 88 04 0a eb } //01 00 
		$a_01_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}