
rule Trojan_Win64_MultiLoader_A{
	meta:
		description = "Trojan:Win64/MultiLoader.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {48 8b c8 48 8b d8 48 63 78 90 01 01 48 03 f8 48 8b d7 e8 90 01 04 8b 57 28 48 03 d3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}