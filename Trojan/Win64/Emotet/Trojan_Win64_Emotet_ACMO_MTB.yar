
rule Trojan_Win64_Emotet_ACMO_MTB{
	meta:
		description = "Trojan:Win64/Emotet.ACMO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c2 48 6b c0 90 01 01 48 2b c8 0f b6 04 19 42 32 44 0e ff 44 3b c7 41 88 41 ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}