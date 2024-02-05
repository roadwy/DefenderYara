
rule Trojan_Win32_TrickBotCrypt_FL_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.FL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 5d ec 2b 1d 90 01 04 2b 1d 90 01 04 03 df 2b 1d 90 01 04 8b 3d 90 01 04 03 fb 03 f7 2b 35 90 01 04 03 f0 2b 35 90 01 04 2b 35 90 01 04 2b f2 2b 35 90 01 04 8b 55 0c 88 0c 32 e9 90 00 } //01 00 
		$a_81_1 = {63 30 63 62 35 3e 6a 29 3f 7a 29 6c 6e 24 4b 72 6d 35 6b 44 28 69 25 2b 38 4d 6b 70 41 4a 68 4b 24 5e 48 30 39 46 } //00 00 
	condition:
		any of ($a_*)
 
}