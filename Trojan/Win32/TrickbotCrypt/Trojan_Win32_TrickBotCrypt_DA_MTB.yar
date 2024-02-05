
rule Trojan_Win32_TrickBotCrypt_DA_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b6 04 0e 0f b6 0c 0f 03 c1 99 b9 90 01 04 f7 f9 88 54 24 90 01 01 ff d3 ff d3 ff d3 0f b6 54 24 90 01 01 8b 0d 90 01 04 8b 44 24 90 01 01 8a 14 0a 30 14 28 90 00 } //01 00 
		$a_03_1 = {8a 04 33 f6 d0 8b ce 3b f7 73 90 01 01 8a d9 2a da 32 19 32 d8 88 19 03 4d 90 01 01 3b cf 72 90 01 01 8b 5d 90 01 01 46 ff 4d 90 01 01 75 90 00 } //01 00 
		$a_03_2 = {8a 04 33 f6 d0 8b ce 3b 75 90 01 01 73 90 01 01 8a d9 2a da 32 19 32 d8 88 19 03 cf 3b 4d 90 01 01 72 90 01 01 8b 5d 90 01 01 46 ff 4d 90 01 01 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}