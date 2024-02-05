
rule Trojan_Win64_TrickBot_CO_MTB{
	meta:
		description = "Trojan:Win64/TrickBot.CO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {48 8b 44 24 90 01 01 48 8b 4c 24 90 01 01 48 03 c8 48 8b c1 8a 40 01 88 44 24 90 01 01 0f b6 44 24 90 01 01 83 e8 90 01 01 6b c0 90 01 01 ba 7f 00 00 00 8b c8 e8 90 01 04 48 8b 4c 24 90 01 01 48 8b 54 24 90 01 01 48 03 d1 48 8b ca 88 41 01 eb a8 90 00 } //01 00 
		$a_03_1 = {99 b9 7f 00 00 00 f7 f9 8b c2 88 44 24 90 01 01 b8 01 00 00 00 48 6b c0 01 48 8d 0d 90 01 04 0f b6 04 01 6b c0 90 01 01 83 c0 90 01 01 99 b9 7f 00 00 00 f7 f9 8b c2 88 44 24 90 01 01 b8 01 00 00 00 48 6b c0 02 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}