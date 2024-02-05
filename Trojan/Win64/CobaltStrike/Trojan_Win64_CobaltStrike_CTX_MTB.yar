
rule Trojan_Win64_CobaltStrike_CTX_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.CTX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {49 ff c0 f7 ed c1 fa 02 8b c2 c1 e8 1f 03 d0 8b c5 ff c5 8d 0c d2 03 c9 2b c1 48 63 c8 48 8b 44 24 38 42 0f b6 8c 31 e0 eb 00 00 41 32 4c 00 ff 41 88 4c 18 ff 3b 6c 24 30 72 c0 } //00 00 
	condition:
		any of ($a_*)
 
}