
rule Trojan_Win32_EmotetCrypt_PCE_MTB{
	meta:
		description = "Trojan:Win32/EmotetCrypt.PCE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {0f b6 c1 8b cf 33 d2 0f b6 0c 19 03 c1 f7 35 90 01 04 8b 4c 24 20 03 54 24 18 0f b6 04 1a 02 44 24 24 32 44 31 ff 88 46 ff 90 00 } //01 00 
		$a_01_1 = {0f b6 14 37 0f b6 c0 03 c2 33 d2 f7 f1 89 54 24 18 ff d3 } //01 00 
		$a_01_2 = {ff d3 8b 44 24 24 8b 4c 24 18 0f b6 14 01 8b 4c 24 10 32 14 31 83 c0 01 83 6c 24 14 01 88 50 ff } //00 00 
	condition:
		any of ($a_*)
 
}