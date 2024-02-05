
rule Trojan_Win32_Emotetcrypt_GS_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.GS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b6 14 1a 03 c2 99 f7 fd 8b ea 8b 15 90 01 04 8b c2 0f af c2 0f af c1 8d 44 40 90 01 01 0f af c6 03 e8 8b c7 0f af c1 83 c0 03 0f af 05 90 01 04 8d 04 40 03 e8 8d 04 bd 90 01 04 2b e8 8b 44 24 90 01 01 2b ea 03 e9 8a 0c 2b 30 08 90 00 } //01 00 
		$a_81_1 = {5a 4a 36 53 6a 68 4b 30 5f 23 72 39 45 24 6f 75 3e 78 30 64 76 63 5a 3f 53 44 64 26 34 67 72 21 29 51 49 24 6f 6c 66 72 6e 3f 76 39 65 65 } //00 00 
	condition:
		any of ($a_*)
 
}