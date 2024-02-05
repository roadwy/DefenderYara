
rule Trojan_Win64_Emotet_PBE_MTB{
	meta:
		description = "Trojan:Win64/Emotet.PBE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {4c 8b c8 48 2b f8 41 8b c0 41 83 c0 90 01 01 99 83 e2 90 01 01 03 c2 83 e0 90 01 01 2b c2 48 63 c8 48 8d 05 90 02 04 8a 04 01 42 32 04 0f 41 88 01 49 83 c1 90 01 01 44 3b c6 72 90 00 } //01 00 
		$a_03_1 = {41 f7 e8 c1 fa 90 01 01 8b c2 c1 e8 90 01 01 03 d0 49 63 c0 41 83 c0 90 01 01 48 63 ca 48 6b c9 90 01 01 48 03 c8 48 8d 05 90 02 04 8a 04 01 42 32 04 0f 41 88 01 49 83 c1 90 01 01 44 3b c6 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}