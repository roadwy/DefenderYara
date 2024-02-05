
rule Trojan_Win64_Emotet_NR_MTB{
	meta:
		description = "Trojan:Win64/Emotet.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {ff c7 c1 fa 90 01 01 8b c2 c1 e8 90 01 01 03 d0 6b c2 90 01 01 2b c8 48 63 c1 48 8d 0d 90 01 04 8a 04 08 42 32 04 36 41 88 06 49 ff c6 3b fd 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}