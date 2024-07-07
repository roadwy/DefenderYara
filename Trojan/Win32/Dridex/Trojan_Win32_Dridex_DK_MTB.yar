
rule Trojan_Win32_Dridex_DK_MTB{
	meta:
		description = "Trojan:Win32/Dridex.DK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 04 00 00 "
		
	strings :
		$a_00_0 = {8a 5d fb 32 5d fb 88 5d fb 89 45 ec } //10
		$a_80_1 = {44 6f 6f 72 72 6c 65 64 46 67 70 70 72 } //DoorrledFgppr  3
		$a_80_2 = {47 70 65 72 6e 66 65 64 65 65 66 65 2e 70 64 62 } //Gpernfedeefe.pdb  3
		$a_80_3 = {6b 65 72 6e 65 6c 33 32 2e 53 6c 65 65 70 } //kernel32.Sleep  3
	condition:
		((#a_00_0  & 1)*10+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3) >=19
 
}
rule Trojan_Win32_Dridex_DK_MTB_2{
	meta:
		description = "Trojan:Win32/Dridex.DK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_80_0 = {6c 6c 69 74 50 6f 52 69 63 79 2e 31 38 39 } //llitPoRicy.189  3
		$a_80_1 = {70 70 67 74 6d 76 2e 70 64 62 } //ppgtmv.pdb  3
		$a_80_2 = {38 74 68 65 7a 62 79 66 6f 72 6b 65 64 6f 74 6f } //8thezbyforkedoto  3
		$a_80_3 = {4d 70 72 41 64 6d 69 6e 4d 49 42 42 75 66 66 65 72 46 72 65 65 } //MprAdminMIBBufferFree  3
		$a_80_4 = {53 63 72 6f 6c 6c 43 6f 6e 73 6f 6c 65 53 63 72 65 65 6e 42 75 66 66 65 72 41 } //ScrollConsoleScreenBufferA  3
		$a_80_5 = {53 65 74 75 70 44 69 47 65 74 44 65 76 69 63 65 49 6e 73 74 61 6c 6c 50 61 72 61 6d 73 41 } //SetupDiGetDeviceInstallParamsA  3
		$a_80_6 = {51 75 65 72 79 55 73 65 72 73 4f 6e 45 6e 63 72 79 70 74 65 64 46 69 6c 65 } //QueryUsersOnEncryptedFile  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3) >=21
 
}
rule Trojan_Win32_Dridex_DK_MTB_3{
	meta:
		description = "Trojan:Win32/Dridex.DK!MTB,SIGNATURE_TYPE_PEHSTR,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {45 6f 72 65 63 65 69 76 69 6e 67 66 74 68 65 49 54 72 69 6e 69 74 79 } //1 EoreceivingftheITrinity
		$a_01_1 = {61 6e 64 6f 66 69 73 63 6f 66 66 65 65 31 73 70 69 72 69 74 4e } //1 andofiscoffee1spiritN
		$a_01_2 = {42 65 74 61 47 63 61 72 74 6d 61 6e 50 54 68 65 73 65 4d 6f 7a 69 6c 6c 61 49 77 68 69 63 68 70 6f 70 75 6c 61 72 } //1 BetaGcartmanPTheseMozillaIwhichpopular
		$a_01_3 = {69 6e 63 6c 75 64 65 64 66 6f 6f 74 62 61 6c 6c 47 6f 6f 67 6c 65 74 68 65 38 50 46 65 62 72 75 61 72 79 61 6e 64 36 35 } //1 includedfootballGooglethe8PFebruaryand65
		$a_01_4 = {30 62 79 74 69 6d 65 65 6e 67 69 6e 65 6a 61 6e 69 6d 61 6c 70 77 69 74 68 41 55 } //1 0bytimeenginejanimalpwithAU
		$a_01_5 = {74 68 65 37 53 65 72 76 65 72 77 61 73 69 73 61 6e 67 65 6c 61 4d 61 79 4d } //1 the7ServerwasisangelaMayM
		$a_01_6 = {53 6d 61 76 65 72 69 63 6b 42 74 68 65 69 72 50 77 6e 32 4f 77 6e 75 73 65 72 6d 61 73 74 65 72 74 68 65 43 68 72 6f 6d 65 57 } //1 SmaverickBtheirPwn2OwnusermastertheChromeW
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}