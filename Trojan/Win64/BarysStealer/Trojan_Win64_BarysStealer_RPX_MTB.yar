
rule Trojan_Win64_BarysStealer_RPX_MTB{
	meta:
		description = "Trojan:Win64/BarysStealer.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {ff c7 83 ff 03 72 9b 45 85 ff 0f 85 85 fe ff ff 48 8b 55 f8 48 83 fa 10 0f 82 b2 fe ff ff 48 ff c2 48 8b 4d e0 48 8b c1 48 81 fa 00 10 00 00 0f 82 96 fe ff ff 48 83 c2 27 48 8b 49 f8 48 2b c1 48 83 c0 f8 48 83 f8 1f } //00 00 
	condition:
		any of ($a_*)
 
}