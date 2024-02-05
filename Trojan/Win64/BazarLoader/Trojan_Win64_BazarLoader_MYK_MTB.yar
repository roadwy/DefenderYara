
rule Trojan_Win64_BazarLoader_MYK_MTB{
	meta:
		description = "Trojan:Win64/BazarLoader.MYK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 d2 41 8b c1 4d 63 c1 f7 f7 45 88 0c 18 44 8b 15 90 02 04 0f b6 14 32 41 83 c1 01 45 3b ca 43 88 14 18 72 90 00 } //01 00 
		$a_03_1 = {4c 63 cf 33 d2 83 c7 01 45 0f b6 04 19 43 0f be 04 19 03 c5 41 03 c0 41 f7 f2 48 63 ea 0f b6 44 1d 00 41 88 04 19 44 88 44 1d 00 44 8b 15 90 02 04 41 3b fa 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}