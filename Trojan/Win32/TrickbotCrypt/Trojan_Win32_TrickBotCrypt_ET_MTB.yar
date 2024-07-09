
rule Trojan_Win32_TrickBotCrypt_ET_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.ET!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 0c 08 32 0c 16 8b 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 8b 75 ec 2b f0 03 f2 2b 35 ?? ?? ?? ?? 2b 35 ?? ?? ?? ?? 03 35 ?? ?? ?? ?? 2b 35 ?? ?? ?? ?? 8b 55 0c 88 0c 32 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_TrickBotCrypt_ET_MTB_2{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.ET!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 c0 81 e2 ff 00 00 00 8a 04 0e 03 c2 33 d2 f7 35 ?? ?? ?? ?? 8a 04 0a 8a 13 32 d0 8b 44 24 ?? 45 88 13 90 09 04 00 8b 54 24 } //1
		$a_81_1 = {31 59 34 4f 47 26 77 73 26 56 44 6c 79 3e 71 3e 62 29 57 76 52 33 48 63 5a 36 49 67 72 78 4e 55 49 47 62 5f 37 30 47 74 49 26 38 65 4a 23 2a 35 40 43 69 2a 61 72 46 37 48 46 70 } //1 1Y4OG&ws&VDly>q>b)WvR3HcZ6IgrxNUIGb_70GtI&8eJ#*5@Ci*arF7HFp
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}