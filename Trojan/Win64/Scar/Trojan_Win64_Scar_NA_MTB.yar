
rule Trojan_Win64_Scar_NA_MTB{
	meta:
		description = "Trojan:Win64/Scar.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 06 00 00 "
		
	strings :
		$a_01_0 = {48 bf 32 a2 df 2d 99 2b 00 00 48 3b c7 74 0c 48 f7 d0 48 89 05 38 19 00 00 eb 76 48 8d 4c 24 30 ff 15 eb d8 ff ff 48 8b 5c 24 30 ff 15 e8 d8 ff ff 44 8b d8 49 33 db ff 15 e4 d8 ff ff 44 8b d8 49 33 db ff 15 e0 d8 ff ff 48 8d 4c 24 38 44 8b d8 49 33 db ff 15 d7 d8 ff ff 4c 8b 5c 24 38 4c 33 db 48 b8 ff } //3
		$a_01_1 = {49 6e 74 65 72 6e 65 74 20 42 61 63 6b 67 61 6d 6d 6f 6e } //1 Internet Backgammon
		$a_01_2 = {6d 00 62 00 63 00 6b 00 67 00 5f 00 7a 00 6d 00 5f 00 2a 00 2a 00 2a 00 } //1 mbckg_zm_***
		$a_01_3 = {71 77 78 30 58 } //1 qwx0X
		$a_01_4 = {51 00 75 00 61 00 73 00 69 00 43 00 68 00 61 00 74 00 } //1 QuasiChat
		$a_01_5 = {47 65 74 53 74 61 72 74 75 70 49 6e 66 6f 57 } //1 GetStartupInfoW
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=8
 
}