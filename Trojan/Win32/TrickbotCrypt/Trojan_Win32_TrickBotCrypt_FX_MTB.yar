
rule Trojan_Win32_TrickBotCrypt_FX_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.FX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {8a 04 37 8a 14 2e 03 c2 33 d2 f7 35 90 01 04 03 ca 8b 15 90 01 04 2b ca 8a 04 31 8a 0b 32 c8 8b 44 24 10 88 0b 90 00 } //05 00 
		$a_81_1 = {44 30 63 6b 2a 3c 3e 24 47 66 55 4f 4a 32 59 66 29 4e 5f 45 3c 52 5e 55 32 3e 6d 45 21 45 51 2a 2a 2a 75 54 75 2a 44 5f 58 6d 25 57 72 76 53 36 4e 34 6c 39 70 } //00 00  D0ck*<>$GfUOJ2Yf)N_E<R^U2>mE!EQ***uTu*D_Xm%WrvS6N4l9p
	condition:
		any of ($a_*)
 
}