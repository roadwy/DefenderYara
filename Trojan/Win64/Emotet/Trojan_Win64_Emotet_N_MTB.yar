
rule Trojan_Win64_Emotet_N_MTB{
	meta:
		description = "Trojan:Win64/Emotet.N!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {f7 ee c1 fa 03 8b c2 c1 e8 1f 03 d0 8b c6 ff c6 8d 0c d2 c1 e1 02 2b c1 48 63 c8 42 8a 04 09 43 32 04 02 41 88 00 } //00 00 
	condition:
		any of ($a_*)
 
}