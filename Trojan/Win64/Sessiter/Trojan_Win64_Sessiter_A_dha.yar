
rule Trojan_Win64_Sessiter_A_dha{
	meta:
		description = "Trojan:Win64/Sessiter.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {b9 cd ff 00 00 66 89 8c 04 90 01 04 b8 02 00 00 00 48 6b c0 01 b9 cc ff 00 00 66 89 8c 04 90 01 04 b8 02 00 00 00 48 6b c0 02 b9 93 ff 00 00 66 89 8c 04 90 01 04 b8 02 00 00 00 48 6b c0 03 b9 9a ff 00 00 66 89 8c 04 90 01 04 b8 02 00 00 00 48 6b c0 04 b9 91 ff 00 00 90 00 } //01 00 
		$a_03_1 = {c1 e0 14 8b 0c 24 c1 e9 0c 0b c1 89 04 24 48 8b 44 24 90 01 01 0f be 00 83 f8 61 7c 90 01 01 48 8b 44 24 90 01 01 0f be 00 83 e8 20 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}