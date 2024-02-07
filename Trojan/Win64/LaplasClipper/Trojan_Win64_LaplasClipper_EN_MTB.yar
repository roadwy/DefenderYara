
rule Trojan_Win64_LaplasClipper_EN_MTB{
	meta:
		description = "Trojan:Win64/LaplasClipper.EN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {36 73 4b 6f 56 75 75 42 73 6c 5f 4b 50 2d 79 68 65 58 35 50 2f 5a 4e 6b 39 30 48 4a 36 66 52 30 6a 68 4d 76 54 35 55 31 65 2f 31 2d 5a 64 2d 69 4a 43 6b 63 49 45 54 51 52 35 4f 65 50 58 2f 56 56 33 78 4b 31 33 6a 57 54 35 70 52 6b 5f 42 54 6f 61 67 } //01 00  6sKoVuuBsl_KP-yheX5P/ZNk90HJ6fR0jhMvT5U1e/1-Zd-iJCkcIETQR5OePX/VV3xK13jWT5pRk_BToag
		$a_81_1 = {6c 61 70 6c 61 73 62 75 69 6c 64 2f 63 6c 69 70 62 6f 61 72 64 } //01 00  laplasbuild/clipboard
		$a_01_2 = {47 65 74 43 6c 69 70 62 6f 61 72 64 44 61 74 61 } //01 00  GetClipboardData
		$a_01_3 = {47 65 74 43 6f 6d 70 75 74 65 72 4e 61 6d 65 57 } //01 00  GetComputerNameW
		$a_01_4 = {53 65 74 2d 43 6f 6f 6b 69 65 55 73 65 72 2d 41 67 65 6e 74 57 } //00 00  Set-CookieUser-AgentW
	condition:
		any of ($a_*)
 
}