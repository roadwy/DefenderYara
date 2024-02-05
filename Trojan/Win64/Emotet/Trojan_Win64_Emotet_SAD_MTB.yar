
rule Trojan_Win64_Emotet_SAD_MTB{
	meta:
		description = "Trojan:Win64/Emotet.SAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c2 c1 e8 90 01 01 03 d0 48 90 01 02 48 90 01 03 48 90 01 02 48 90 01 02 42 90 01 04 43 90 01 03 41 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}