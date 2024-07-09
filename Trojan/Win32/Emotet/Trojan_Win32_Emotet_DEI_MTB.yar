
rule Trojan_Win32_Emotet_DEI_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DEI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_02_0 = {03 c1 99 b9 ?? ?? ?? ?? f7 f9 8b 44 24 20 8b 4c 24 28 (40|83 c0 01) 89 44 24 20 8a 54 14 30 30 54 01 ff } //2
		$a_81_1 = {4b 57 6f 41 62 48 73 43 54 34 71 6b 35 58 68 66 65 48 70 71 41 77 34 43 6d 38 45 79 37 79 79 34 76 41 4b 74 78 34 6e 5a 6e 50 37 43 6c } //2 KWoAbHsCT4qk5XhfeHpqAw4Cm8Ey7yy4vAKtx4nZnP7Cl
		$a_01_2 = {68 00 67 00 63 00 66 00 73 00 67 00 68 00 64 00 66 00 61 00 73 00 67 00 68 00 64 00 } //1 hgcfsghdfasghd
		$a_01_3 = {68 00 67 00 64 00 67 00 68 00 64 00 68 00 67 00 64 00 68 00 67 00 64 00 68 00 67 00 64 00 } //1 hgdghdhgdhgdhgd
	condition:
		((#a_02_0  & 1)*2+(#a_81_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=2
 
}