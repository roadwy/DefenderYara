
rule Trojan_Win64_Emotet_BN_MTB{
	meta:
		description = "Trojan:Win64/Emotet.BN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {8b c2 c1 e8 90 01 01 03 d0 6b c2 90 01 01 8b d3 ff c3 2b d0 48 8b 05 90 01 04 4c 63 c2 41 8a 14 00 90 03 04 03 41 32 14 3f 32 14 3e 88 17 48 ff c7 49 ff 90 03 01 01 ce cf 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}