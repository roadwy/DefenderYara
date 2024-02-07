
rule Trojan_Win32_TrickBotCrypt_EK_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.EK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b6 55 ff 83 ea 69 88 55 ff 6a 12 e8 90 01 04 83 c4 04 0f b6 45 ff 0f b6 4d fe 0b c8 88 4d fe 68 0a 01 00 00 e8 90 01 04 83 c4 04 0f b6 55 fd 0f b6 45 fe 33 c2 88 45 fe 68 12 01 00 00 e8 90 01 04 83 c4 04 8a 4d fd 80 c1 01 88 4d fd 6a 4a e8 90 01 04 83 c4 04 8b 55 f4 8a 45 fe 88 02 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_TrickBotCrypt_EK_MTB_2{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.EK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 c8 8b 15 90 01 04 0f af 15 90 01 04 03 ca a1 90 01 04 0f af 05 90 01 04 03 45 0c 8b 55 e4 8b 12 8b 75 08 33 db 8a 1c 16 03 1d 90 01 04 8a 04 08 32 c3 90 00 } //01 00 
		$a_81_1 = {6d 67 49 4c 25 5e 51 39 25 61 21 76 68 46 34 35 36 33 5f 58 23 23 25 6f 5e 6d 6d 7a 42 6b 6c 33 72 41 71 72 39 46 28 5e 47 35 2a 29 46 44 67 4a 4a 75 62 64 3c 2b 73 4b 3c 33 6f 66 6c 45 26 5a 43 43 73 70 41 58 44 48 50 3f 62 48 33 65 53 47 50 37 37 26 34 75 6b 63 66 23 36 } //00 00  mgIL%^Q9%a!vhF4563_X##%o^mmzBkl3rAqr9F(^G5*)FDgJJubd<+sK<3oflE&ZCCspAXDHP?bH3eSGP77&4ukcf#6
	condition:
		any of ($a_*)
 
}