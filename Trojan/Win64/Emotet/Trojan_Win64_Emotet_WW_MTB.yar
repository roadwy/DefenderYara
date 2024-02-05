
rule Trojan_Win64_Emotet_WW_MTB{
	meta:
		description = "Trojan:Win64/Emotet.WW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {49 8b ca 49 83 c1 90 01 01 49 83 c2 90 01 01 41 f7 e0 c1 ea 90 01 01 41 83 c0 90 01 01 8b c2 48 6b c0 90 01 01 48 2b c8 0f b6 04 19 42 32 44 0e ff 44 3b c7 41 88 41 ff 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}