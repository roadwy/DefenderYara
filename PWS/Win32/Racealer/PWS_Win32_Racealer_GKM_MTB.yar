
rule PWS_Win32_Racealer_GKM_MTB{
	meta:
		description = "PWS:Win32/Racealer.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {b8 f8 94 08 00 01 45 ?? 8b 45 ?? 8a 04 30 8b 0d ?? ?? ?? ?? 88 04 31 81 3d ?? ?? ?? ?? 03 02 00 00 75 ?? 53 53 ff 15 ?? ?? ?? ?? 89 1d ?? ?? ?? ?? 46 3b 35 ?? ?? ?? ?? 72 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule PWS_Win32_Racealer_GKM_MTB_2{
	meta:
		description = "PWS:Win32/Racealer.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 11 00 00 "
		
	strings :
		$a_80_0 = {5c 47 6f 6f 67 6c 65 5c 43 68 72 6f 6d 65 5c 55 73 65 72 20 44 61 74 61 } //\Google\Chrome\User Data  1
		$a_80_1 = {5c 4d 69 63 72 6f 73 6f 66 74 5c 45 64 67 65 5c 55 73 65 72 20 44 61 74 61 } //\Microsoft\Edge\User Data  1
		$a_80_2 = {5c 43 6f 6d 6f 64 6f 5c 44 72 61 67 6f 6e 5c 55 73 65 72 20 44 61 74 61 } //\Comodo\Dragon\User Data  1
		$a_80_3 = {5c 54 65 6e 63 65 6e 74 5c 51 51 42 72 6f 77 73 65 72 5c 55 73 65 72 20 44 61 74 61 } //\Tencent\QQBrowser\User Data  1
		$a_80_4 = {4c 6f 67 69 6e 20 44 61 74 61 } //Login Data  1
		$a_80_5 = {43 6f 6f 6b 69 65 73 } //Cookies  1
		$a_80_6 = {69 6d 61 67 65 2f 6a 70 65 67 } //image/jpeg  1
		$a_80_7 = {53 4d 54 50 20 45 6d 61 69 6c 20 41 64 64 72 65 73 73 } //SMTP Email Address  1
		$a_80_8 = {48 54 54 50 4d 61 69 6c 20 55 73 65 72 20 4e 61 6d 65 } //HTTPMail User Name  1
		$a_80_9 = {48 54 54 50 4d 61 69 6c 20 50 61 73 73 77 6f 72 64 32 } //HTTPMail Password2  1
		$a_80_10 = {69 6e 65 74 63 6f 6d 6d 20 73 65 72 76 65 72 20 70 61 73 73 77 6f 72 64 73 } //inetcomm server passwords  1
		$a_80_11 = {6f 75 74 6c 6f 6f 6b 20 61 63 63 6f 75 6e 74 20 6d 61 6e 61 67 65 72 20 70 61 73 73 77 6f 72 64 73 } //outlook account manager passwords  1
		$a_80_12 = {57 65 62 20 44 61 74 61 2e 2a } //Web Data.*  1
		$a_80_13 = {45 54 20 77 41 4c 4c 45 54 53 7c 65 4c 45 43 54 52 55 21 4c 40 42 49 48 4f 44 48 4f 47 4e } //ET wALLETS|eLECTRU!L@BIHODHOGN  1
		$a_80_14 = {6d 61 63 68 69 6e 65 69 6e 66 6f 2e 74 78 74 } //machineinfo.txt  1
		$a_80_15 = {73 63 72 65 65 6e 2e 6a 70 65 67 } //screen.jpeg  1
		$a_80_16 = {77 61 6c 6c 65 74 73 5c } //wallets\  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1+(#a_80_10  & 1)*1+(#a_80_11  & 1)*1+(#a_80_12  & 1)*1+(#a_80_13  & 1)*1+(#a_80_14  & 1)*1+(#a_80_15  & 1)*1+(#a_80_16  & 1)*1) >=17
 
}
rule PWS_Win32_Racealer_GKM_MTB_3{
	meta:
		description = "PWS:Win32/Racealer.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 12 00 00 "
		
	strings :
		$a_80_0 = {69 6d 61 67 65 2f 6a 70 65 67 } //image/jpeg  1
		$a_80_1 = {69 6e 65 74 63 6f 6d 6d 20 73 65 72 76 65 72 20 70 61 73 73 77 6f 72 64 73 } //inetcomm server passwords  1
		$a_80_2 = {6f 75 74 6c 6f 6f 6b 20 61 63 63 6f 75 6e 74 20 6d 61 6e 61 67 65 72 20 70 61 73 73 77 6f 72 64 73 } //outlook account manager passwords  1
		$a_80_3 = {5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 41 63 63 6f 75 6e 74 20 4d 61 6e 61 67 65 72 5c 41 63 63 6f 75 6e 74 73 } //\Software\Microsoft\Internet Account Manager\Accounts  1
		$a_80_4 = {6d 61 63 68 69 6e 65 69 6e 66 6f 2e 74 78 74 } //machineinfo.txt  1
		$a_80_5 = {73 63 72 65 65 6e 2e 6a 70 65 67 } //screen.jpeg  1
		$a_80_6 = {4c 6f 67 69 6e 20 44 61 74 61 } //Login Data  1
		$a_80_7 = {43 6f 6f 6b 69 65 73 } //Cookies  1
		$a_80_8 = {43 6f 6f 6b 69 65 73 2e 2a } //Cookies.*  1
		$a_80_9 = {57 65 62 20 44 61 74 61 2e 2a } //Web Data.*  1
		$a_80_10 = {77 61 6c 6c 65 74 73 5c } //wallets\  1
		$a_80_11 = {5c 47 6f 6f 67 6c 65 5c 43 68 72 6f 6d 65 5c 55 73 65 72 20 44 61 74 61 } //\Google\Chrome\User Data  1
		$a_80_12 = {5c 4d 69 63 72 6f 73 6f 66 74 5c 45 64 67 65 5c 55 73 65 72 20 44 61 74 61 } //\Microsoft\Edge\User Data  1
		$a_80_13 = {5c 43 6f 6d 6f 64 6f 5c 44 72 61 67 6f 6e 5c 55 73 65 72 20 44 61 74 61 } //\Comodo\Dragon\User Data  1
		$a_80_14 = {5c 42 72 61 76 65 53 6f 66 74 77 61 72 65 5c 42 72 61 76 65 2d 42 72 6f 77 73 65 72 5c 55 73 65 72 20 44 61 74 61 } //\BraveSoftware\Brave-Browser\User Data  1
		$a_80_15 = {5c 53 61 66 65 72 20 54 65 63 68 6e 6f 6c 6f 67 69 65 73 5c 53 65 63 75 72 65 20 42 72 6f 77 73 65 72 5c 55 73 65 72 20 44 61 74 61 } //\Safer Technologies\Secure Browser\User Data  1
		$a_80_16 = {5c 54 65 6e 63 65 6e 74 5c 51 51 42 72 6f 77 73 65 72 5c 55 73 65 72 20 44 61 74 61 } //\Tencent\QQBrowser\User Data  1
		$a_02_17 = {f6 d1 30 4c 15 ?? 42 83 fa 05 73 ?? 8a 4d ?? eb } //1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1+(#a_80_10  & 1)*1+(#a_80_11  & 1)*1+(#a_80_12  & 1)*1+(#a_80_13  & 1)*1+(#a_80_14  & 1)*1+(#a_80_15  & 1)*1+(#a_80_16  & 1)*1+(#a_02_17  & 1)*1) >=18
 
}