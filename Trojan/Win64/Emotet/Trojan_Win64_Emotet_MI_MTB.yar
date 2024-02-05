
rule Trojan_Win64_Emotet_MI_MTB{
	meta:
		description = "Trojan:Win64/Emotet.MI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 04 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8b c2 c1 e8 90 01 01 03 d0 6b c2 90 01 01 2b c8 48 63 c1 48 8d 0d 90 01 04 8a 04 08 42 32 04 36 41 88 06 49 ff c6 3b fd 72 90 00 } //0a 00 
		$a_03_1 = {4d 8d 40 01 f7 e6 8b ce ff c6 c1 ea 90 01 01 6b c2 90 01 01 2b c8 48 63 c1 42 0f b6 04 10 43 32 44 07 ff 41 88 40 ff 41 3b f4 72 90 00 } //0a 00 
		$a_03_2 = {41 f7 e8 41 03 d0 c1 fa 90 01 01 8b c2 c1 e8 90 01 01 03 d0 41 8b c0 41 ff c0 6b d2 90 01 01 2b c2 48 63 c8 48 8d 05 90 01 04 8a 04 01 42 32 04 16 41 88 02 49 ff c2 44 3b c5 72 90 00 } //0a 00 
		$a_03_3 = {4d 8d 40 01 f7 e6 8b c6 ff c6 c1 ea 90 01 01 8d 0c d2 03 c9 2b c1 48 63 c8 42 0f b6 04 11 43 32 44 07 ff 41 88 40 ff 41 3b f4 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}