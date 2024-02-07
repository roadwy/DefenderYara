
rule Trojan_Win64_CobaltStrike_KK_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {41 b9 04 00 00 00 41 b8 00 30 00 00 48 89 c2 b9 00 00 00 00 48 8b 90 01 05 ff 90 00 } //01 00 
		$a_01_1 = {4c 6f 61 64 65 72 2e 6e 69 6d } //01 00  Loader.nim
		$a_01_2 = {62 63 6d 6f 64 65 2e 6e 69 6d } //00 00  bcmode.nim
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_CobaltStrike_KK_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {b8 93 24 49 92 41 f7 e8 41 03 d0 c1 fa 05 8b c2 c1 e8 1f 03 d0 41 8b c0 41 ff c0 6b d2 38 2b c2 48 63 c8 48 8d 05 b4 20 02 00 8a 04 01 42 32 04 0e 41 88 01 49 ff c1 44 3b c5 72 c4 } //00 00 
	condition:
		any of ($a_*)
 
}