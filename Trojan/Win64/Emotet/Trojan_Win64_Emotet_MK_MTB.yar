
rule Trojan_Win64_Emotet_MK_MTB{
	meta:
		description = "Trojan:Win64/Emotet.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 0a 00 "
		
	strings :
		$a_03_0 = {48 ff c6 41 f7 e1 2b ca 41 8b c1 d1 e9 41 ff c1 03 ca c1 e9 90 01 01 6b c9 90 01 01 2b c1 48 63 c8 42 0f b6 04 11 32 46 ff 41 88 44 30 ff 44 3b cd 72 90 00 } //0a 00 
		$a_03_1 = {48 ff c3 41 f7 e3 41 8b c3 41 ff c3 c1 ea 90 01 01 6b d2 90 01 01 2b c2 48 63 c8 42 0f b6 04 09 41 32 44 18 ff 88 43 ff 44 3b de 72 90 00 } //0a 00 
		$a_03_2 = {0f b6 04 01 89 44 24 2c 8b 44 24 20 99 b9 90 01 04 f7 f9 8b c2 48 98 48 8b 4c 24 40 0f b6 04 01 8b 4c 24 2c 33 c8 8b c1 8b 0d 90 01 04 0f af 0d 90 01 04 8b 54 24 20 2b d1 8b ca 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}