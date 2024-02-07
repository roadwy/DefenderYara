
rule Trojan_Win64_Trickbot_CK_MTB{
	meta:
		description = "Trojan:Win64/Trickbot.CK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {c7 44 24 48 60 73 65 00 b9 f8 2a 00 00 ff 15 90 01 04 8b 05 90 01 04 85 c0 74 eb c7 44 24 90 01 01 53 65 6c 65 8b 44 24 90 01 01 ff c0 89 44 24 90 01 01 c7 44 24 90 01 01 57 61 6e 74 8b 44 24 90 01 01 ff c8 90 00 } //01 00 
		$a_81_1 = {52 65 6c 65 61 73 65 } //01 00  Release
		$a_81_2 = {46 72 65 65 42 75 66 66 65 72 } //00 00  FreeBuffer
	condition:
		any of ($a_*)
 
}