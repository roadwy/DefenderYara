
rule PWS_Win32_RacoonStealer_MK_MTB{
	meta:
		description = "PWS:Win32/RacoonStealer.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,30 02 30 02 2a 00 00 01 00 "
		
	strings :
		$a_80_0 = {47 6f 6f 67 6c 65 5c 43 68 72 6f 6d 65 5c 55 73 65 72 20 44 61 74 61 } //Google\Chrome\User Data  01 00 
		$a_80_1 = {4d 69 63 72 6f 73 6f 66 74 5c 45 64 67 65 5c 55 73 65 72 20 44 61 74 61 } //Microsoft\Edge\User Data  01 00 
		$a_80_2 = {43 68 72 6f 6d 69 75 6d 5c 55 73 65 72 20 44 61 74 61 } //Chromium\User Data  01 00 
		$a_80_3 = {58 70 6f 6d 5c 55 73 65 72 20 44 61 74 61 } //Xpom\User Data  01 00 
		$a_80_4 = {43 6f 6d 6f 64 6f 5c 44 72 61 67 6f 6e 5c 55 73 65 72 20 44 61 74 61 } //Comodo\Dragon\User Data  01 00 
		$a_80_5 = {41 6d 69 67 6f 5c 55 73 65 72 20 44 61 74 61 } //Amigo\User Data  01 00 
		$a_80_6 = {4f 72 62 69 74 75 6d 5c 55 73 65 72 20 44 61 74 61 } //Orbitum\User Data  01 00 
		$a_80_7 = {42 72 6f 6d 69 75 6d 5c 55 73 65 72 20 44 61 74 61 } //Bromium\User Data  01 00 
		$a_80_8 = {42 72 61 76 65 53 6f 66 74 77 61 72 65 5c 42 72 61 76 65 2d 42 72 6f 77 73 65 72 5c 55 73 65 72 20 44 61 74 61 } //BraveSoftware\Brave-Browser\User Data  01 00 
		$a_80_9 = {4e 69 63 68 72 6f 6d 65 5c 55 73 65 72 20 44 61 74 61 } //Nichrome\User Data  01 00 
		$a_80_10 = {52 6f 63 6b 4d 65 6c 74 5c 55 73 65 72 20 44 61 74 61 } //RockMelt\User Data  01 00 
		$a_80_11 = {33 36 30 42 72 6f 77 73 65 72 5c 42 72 6f 77 73 65 72 5c 55 73 65 72 20 44 61 74 61 } //360Browser\Browser\User Data  01 00 
		$a_80_12 = {56 69 76 61 6c 64 69 5c 55 73 65 72 20 44 61 74 61 } //Vivaldi\User Data  01 00 
		$a_80_13 = {47 6f 21 5c 55 73 65 72 20 44 61 74 61 } //Go!\User Data  01 00 
		$a_80_14 = {53 70 75 74 6e 69 6b 5c 53 70 75 74 6e 69 6b 5c 55 73 65 72 20 44 61 74 61 } //Sputnik\Sputnik\User Data  01 00 
		$a_80_15 = {4b 6f 6d 65 74 61 5c 55 73 65 72 20 44 61 74 61 } //Kometa\User Data  01 00 
		$a_80_16 = {75 43 6f 7a 4d 65 64 69 61 5c 55 72 61 6e 5c 55 73 65 72 20 44 61 74 61 } //uCozMedia\Uran\User Data  01 00 
		$a_80_17 = {51 49 50 20 53 75 72 66 5c 55 73 65 72 20 44 61 74 61 } //QIP Surf\User Data  01 00 
		$a_80_18 = {45 70 69 63 20 50 72 69 76 61 63 79 20 42 72 6f 77 73 65 72 5c 55 73 65 72 20 44 61 74 61 } //Epic Privacy Browser\User Data  01 00 
		$a_80_19 = {43 6f 63 43 6f 63 5c 42 72 6f 77 73 65 72 5c 55 73 65 72 20 44 61 74 61 } //CocCoc\Browser\User Data  01 00 
		$a_80_20 = {43 65 6e 74 42 72 6f 77 73 65 72 5c 55 73 65 72 20 44 61 74 61 } //CentBrowser\User Data  01 00 
		$a_80_21 = {37 53 74 61 72 5c 37 53 74 61 72 5c 55 73 65 72 20 44 61 74 61 } //7Star\7Star\User Data  01 00 
		$a_80_22 = {45 6c 65 6d 65 6e 74 73 20 42 72 6f 77 73 65 72 5c 55 73 65 72 20 44 61 74 61 } //Elements Browser\User Data  01 00 
		$a_80_23 = {53 75 68 62 61 5c 55 73 65 72 20 44 61 74 61 } //Suhba\User Data  01 00 
		$a_80_24 = {53 61 66 65 72 20 54 65 63 68 6e 6f 6c 6f 67 69 65 73 5c 53 65 63 75 72 65 20 42 72 6f 77 73 65 72 5c 55 73 65 72 20 44 61 74 61 } //Safer Technologies\Secure Browser\User Data  01 00 
		$a_80_25 = {52 61 66 6f 74 65 63 68 5c 4d 75 73 74 61 6e 67 5c 55 73 65 72 20 44 61 74 61 } //Rafotech\Mustang\User Data  01 00 
		$a_80_26 = {53 75 70 65 72 62 69 72 64 5c 55 73 65 72 20 44 61 74 61 } //Superbird\User Data  01 00 
		$a_80_27 = {43 68 65 64 6f 74 5c 55 73 65 72 20 44 61 74 61 } //Chedot\User Data  01 00 
		$a_80_28 = {54 6f 72 63 68 5c 55 73 65 72 20 44 61 74 61 } //Torch\User Data  01 00 
		$a_80_29 = {54 65 6e 63 65 6e 74 5c 51 51 42 72 6f 77 73 65 72 5c 55 73 65 72 20 44 61 74 61 } //Tencent\QQBrowser\User Data  32 00 
		$a_80_30 = {4c 6f 67 69 6e 20 44 61 74 61 } //Login Data  32 00 
		$a_80_31 = {43 6f 6f 6b 69 65 73 } //Cookies  32 00 
		$a_80_32 = {57 65 62 20 44 61 74 61 } //Web Data  32 00 
		$a_80_33 = {69 6d 61 67 65 2f 6a 70 65 67 } //image/jpeg  32 00 
		$a_80_34 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 49 6e 74 65 6c 6c 69 46 6f 72 6d 73 5c 53 74 6f 72 61 67 65 32 } //Software\Microsoft\Internet Explorer\IntelliForms\Storage2  32 00 
		$a_80_35 = {4d 69 63 72 6f 73 6f 66 74 5f 57 69 6e 49 6e 65 74 5f } //Microsoft_WinInet_  32 00 
		$a_80_36 = {69 6e 65 74 63 6f 6d 6d 20 73 65 72 76 65 72 20 70 61 73 73 77 6f 72 64 73 } //inetcomm server passwords  32 00 
		$a_80_37 = {6f 75 74 6c 6f 6f 6b 20 61 63 63 6f 75 6e 74 20 6d 61 6e 61 67 65 72 20 70 61 73 73 77 6f 72 64 73 } //outlook account manager passwords  32 00 
		$a_80_38 = {64 61 74 61 2e 6a 73 6f 6e } //data.json  32 00 
		$a_80_39 = {73 63 72 65 65 6e 2e 6a 70 65 67 } //screen.jpeg  32 00 
		$a_80_40 = {6d 61 63 68 69 6e 65 69 6e 66 6f 2e 74 78 74 } //machineinfo.txt  32 00 
		$a_80_41 = {77 61 6c 6c 65 74 73 } //wallets  00 00 
	condition:
		any of ($a_*)
 
}