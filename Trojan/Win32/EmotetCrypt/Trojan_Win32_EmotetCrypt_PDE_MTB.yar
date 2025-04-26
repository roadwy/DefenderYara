
rule Trojan_Win32_EmotetCrypt_PDE_MTB{
	meta:
		description = "Trojan:Win32/EmotetCrypt.PDE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {88 0c 3a 33 d2 0f b6 c1 8b ce 0f b6 0c 39 03 c1 f7 35 ?? ?? ?? ?? 8b f2 ff 15 ?? ?? ?? ?? 8b 4d 18 8a 04 0b 32 04 3e 88 01 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_EmotetCrypt_PDE_MTB_2{
	meta:
		description = "Trojan:Win32/EmotetCrypt.PDE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {5a 6f 6d 62 69 66 79 41 63 74 43 74 78 } //1 ZombifyActCtx
		$a_81_1 = {4a 65 74 52 6f 6c 6c 62 61 63 6b } //1 JetRollback
		$a_81_2 = {42 79 62 69 67 43 74 49 58 54 65 34 35 34 74 } //1 BybigCtIXTe454t
		$a_81_3 = {47 65 74 55 73 65 72 47 65 6f 49 44 } //1 GetUserGeoID
		$a_81_4 = {50 6f 73 74 65 64 } //1 Posted
		$a_81_5 = {6d 61 69 6c 63 6f 6d } //1 mailcom
		$a_81_6 = {63 6f 6d 76 69 65 77 } //1 comview
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}