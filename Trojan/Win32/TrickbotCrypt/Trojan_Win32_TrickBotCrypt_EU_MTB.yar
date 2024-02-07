
rule Trojan_Win32_TrickBotCrypt_EU_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.EU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 45 f4 8a 04 30 34 e0 88 45 0f 8b de 85 f6 90 01 02 e8 90 01 04 8b 4d 08 8a 45 0f 3b 75 fc 90 01 02 8a d3 2a d1 80 e2 e0 32 13 32 d0 88 13 03 df 3b 5d fc 90 01 02 46 ff 4d f8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_TrickBotCrypt_EU_MTB_2{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.EU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 c8 8b 45 90 01 01 0f af cb 03 4d f0 03 c1 8a 0c 3a 02 0d 90 01 04 30 08 ff 45 f0 8b 45 f0 3b 45 90 01 01 0f 82 90 09 03 00 89 55 90 00 } //01 00 
		$a_81_1 = {40 66 47 75 2b 6d 6e 64 24 30 25 4f 69 35 4b 33 40 41 64 40 76 58 67 42 48 54 51 7a 21 6c 70 4b 79 61 34 42 47 64 75 70 78 6c 28 35 71 44 38 77 53 50 65 46 29 54 6d 79 66 6b 38 65 69 70 58 76 23 64 54 33 28 42 6d 55 49 28 59 39 30 29 72 73 57 54 51 28 78 2b 70 47 63 58 62 44 30 51 77 6d 51 23 79 6f 6a 71 56 3f 4d 31 34 34 7a 54 25 5e 48 68 } //00 00  @fGu+mnd$0%Oi5K3@Ad@vXgBHTQz!lpKya4BGdupxl(5qD8wSPeF)Tmyfk8eipXv#dT3(BmUI(Y90)rsWTQ(x+pGcXbD0QwmQ#yojqV?M144zT%^Hh
	condition:
		any of ($a_*)
 
}