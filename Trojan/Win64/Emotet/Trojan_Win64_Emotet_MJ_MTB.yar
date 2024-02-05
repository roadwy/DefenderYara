
rule Trojan_Win64_Emotet_MJ_MTB{
	meta:
		description = "Trojan:Win64/Emotet.MJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 0a 00 "
		
	strings :
		$a_03_0 = {41 f7 e8 41 ff c0 c1 fa 90 01 01 8b c2 c1 e8 90 01 01 03 d0 6b c2 90 01 01 2b c8 48 63 c1 48 8d 0d 90 01 04 8a 04 08 41 32 04 2a 41 88 02 49 ff c2 45 3b c6 72 90 00 } //0a 00 
		$a_03_1 = {48 8d 76 01 f7 e7 8b cf ff c7 c1 ea 90 01 01 6b c2 90 01 01 2b c8 48 63 c1 42 0f b6 04 20 41 32 44 36 ff 88 46 ff 41 3b ff 72 90 00 } //0a 00 
		$a_03_2 = {41 f7 e8 c1 fa 90 01 01 8b c2 c1 e8 90 01 01 03 d0 41 8b c0 41 ff c0 6b d2 90 01 01 2b c2 48 63 c8 48 8d 05 90 01 04 8a 04 01 41 32 04 2a 41 88 02 49 ff c2 45 3b c6 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}