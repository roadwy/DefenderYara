
rule Trojan_Win32_TrickBotCrypt_EP_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.EP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 4c 24 24 89 8c 24 94 00 00 00 83 f5 4d 89 6c 24 28 89 ac 24 98 00 00 00 43 89 5c 24 2c 3b 9c 24 80 00 00 00 0f 8c 23 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_TrickBotCrypt_EP_MTB_2{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.EP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b c3 0f af c7 8d 04 58 2b 05 ?? ?? ?? ?? 03 45 f8 03 c2 8b 55 f4 0f b6 14 32 89 45 f0 8b 45 fc 0f b6 04 30 03 c2 33 d2 f7 35 ?? ?? ?? ?? 8b 45 f0 41 0f af cf 2b d1 03 d3 8a 0c 32 30 08 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_TrickBotCrypt_EP_MTB_3{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.EP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {03 d0 8b 0d ?? ?? ?? ?? 0f af 0d ?? ?? ?? ?? 03 d1 a1 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 03 45 0c 8b 4d e4 8b 09 8b 75 08 33 db 8a 1c 0e 03 1d ?? ?? ?? ?? 8a 14 10 32 d3 } //1
		$a_81_1 = {29 6a 51 58 3f 30 4b 6d 23 6b 4f 30 72 61 47 24 40 63 24 26 41 50 56 44 3c 52 4f 4f 53 72 31 68 6a 24 43 43 44 40 6c 32 23 66 59 3c 3e 65 35 3f 43 4e 61 44 5e 30 30 33 77 6e 74 63 7a 4d 47 63 6c 46 48 78 21 42 23 6b 4d 69 2b 69 } //1 )jQX?0Km#kO0raG$@c$&APVD<ROOSr1hj$CCD@l2#fY<>e5?CNaD^003wntczMGclFHx!B#kMi+i
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}