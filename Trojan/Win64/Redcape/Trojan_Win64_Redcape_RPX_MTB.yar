
rule Trojan_Win64_Redcape_RPX_MTB{
	meta:
		description = "Trojan:Win64/Redcape.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {0f d5 f7 41 5f 41 55 66 41 bd 03 00 41 50 45 01 c5 0f 77 41 58 0f f5 eb 41 5d 48 83 34 c1 77 52 48 c7 c2 03 00 00 00 41 53 41 50 41 58 41 5b 48 ff ca 75 f3 5a 48 ff c0 48 83 f8 04 } //00 00 
	condition:
		any of ($a_*)
 
}