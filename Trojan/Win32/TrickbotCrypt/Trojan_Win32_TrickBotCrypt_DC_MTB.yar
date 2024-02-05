
rule Trojan_Win32_TrickBotCrypt_DC_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.DC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 0c 3b 80 f1 20 8b c7 3b fe 73 90 01 01 8d 64 24 00 8a d8 2a da 80 e3 20 32 18 32 d9 88 18 03 45 90 01 01 3b c6 72 90 01 01 8b 5d 90 01 01 47 ff 4d 08 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}