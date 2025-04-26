
rule Trojan_BAT_RedLineStealer_EM_MTB{
	meta:
		description = "Trojan:BAT/RedLineStealer.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_01_0 = {0a 02 8e 69 1b 59 8d 42 00 00 01 0b 02 1b 07 16 02 8e 69 1b 59 28 9f 00 00 0a 00 07 16 14 28 40 00 00 2b 0c 06 06 03 6f a0 00 } //7
	condition:
		((#a_01_0  & 1)*7) >=7
 
}
rule Trojan_BAT_RedLineStealer_EM_MTB_2{
	meta:
		description = "Trojan:BAT/RedLineStealer.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {72 fc a1 01 70 72 00 a2 01 70 6f 3e 01 00 0a 72 04 a2 01 70 72 08 a2 01 70 6f 3e 01 00 0a 0b 73 3f 01 00 0a 0c 07 6f 40 01 00 0a 18 da 13 06 16 13 07 2b 1e 08 07 11 07 18 6f 41 01 00 0a 1f 10 28 42 01 00 0a b4 6f 43 01 00 0a 00 11 07 18 d6 13 07 11 07 11 06 31 dc } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
rule Trojan_BAT_RedLineStealer_EM_MTB_3{
	meta:
		description = "Trojan:BAT/RedLineStealer.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {0a 06 72 55 84 01 70 72 f9 11 00 70 6f 25 01 00 0a 72 59 84 01 70 72 5d 84 01 70 6f 25 01 00 0a 0b 73 26 01 00 0a 0c 07 6f 04 01 00 0a 18 da 13 06 16 13 07 2b 1e 08 07 11 07 18 6f 27 01 00 0a 1f 10 28 28 01 00 0a b4 6f 29 01 00 0a 00 11 07 18 d6 13 07 11 07 11 06 31 dc } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
rule Trojan_BAT_RedLineStealer_EM_MTB_4{
	meta:
		description = "Trojan:BAT/RedLineStealer.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {6c 70 50 72 6f 63 65 73 6e 6f 69 74 63 65 53 63 69 74 73 6f 6e 67 61 69 44 6e 6f 69 74 61 72 75 67 69 66 6e 6f 43 6c 65 64 6f 4d 65 63 69 76 72 65 53 6d 65 74 73 79 53 39 31 34 36 39 } //1 lpProcesnoitceScitsongaiDnoitarugifnoCledoMecivreSmetsyS91469
		$a_81_1 = {48 6f 73 74 54 6f 4e 65 74 77 6f 72 6b 4f 72 64 65 72 } //1 HostToNetworkOrder
		$a_81_2 = {4e 65 74 77 6f 72 6b 54 6f 48 6f 73 74 4f 72 64 65 72 } //1 NetworkToHostOrder
		$a_81_3 = {43 6f 6e 66 75 73 65 72 2e 43 6f 72 65 20 31 2e 36 2e 30 2b 34 34 37 33 34 31 39 36 34 66 } //1 Confuser.Core 1.6.0+447341964f
		$a_81_4 = {41 75 74 61 72 6b 79 2e 65 78 65 } //1 Autarky.exe
		$a_81_5 = {47 65 74 45 78 65 63 75 74 69 6e 67 41 73 73 65 6d 62 6c 79 } //1 GetExecutingAssembly
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}
rule Trojan_BAT_RedLineStealer_EM_MTB_5{
	meta:
		description = "Trojan:BAT/RedLineStealer.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {6c 70 50 72 6f 63 65 73 64 6e 61 6d 6d 6f 43 65 74 61 65 72 43 64 6e 61 6d 6d 6f 43 65 74 61 65 72 43 42 44 49 73 64 6f 68 74 65 4d 65 76 69 74 61 4e 65 66 61 73 6e 55 6e 6f 6d 6d 6f 43 61 74 61 44 6d 65 74 73 79 53 39 38 31 32 34 } //1 lpProcesdnammoCetaerCdnammoCetaerCBDIsdohteMevitaNefasnUnommoCataDmetsyS98124
		$a_81_1 = {43 6f 6e 66 75 73 65 72 2e 43 6f 72 65 20 31 2e 36 2e 30 2b 34 34 37 33 34 31 39 36 34 66 } //1 Confuser.Core 1.6.0+447341964f
		$a_81_2 = {48 74 74 70 55 74 69 6c 69 74 79 } //1 HttpUtility
		$a_81_3 = {48 74 74 70 53 65 72 76 65 72 55 74 69 6c 69 74 79 } //1 HttpServerUtility
		$a_81_4 = {47 65 74 45 78 65 63 75 74 69 6e 67 41 73 73 65 6d 62 6c 79 } //1 GetExecutingAssembly
		$a_81_5 = {43 68 65 76 72 6f 6e 2e 65 78 65 } //1 Chevron.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}
rule Trojan_BAT_RedLineStealer_EM_MTB_6{
	meta:
		description = "Trojan:BAT/RedLineStealer.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {64 6e 6c 69 62 44 6f 74 4e 65 74 50 64 62 } //1 dnlibDotNetPdb
		$a_81_1 = {65 6e 63 72 79 70 74 65 64 5f 6b 65 79 } //1 encrypted_key
		$a_81_2 = {61 75 74 6f 66 69 6c 6c 50 72 6f 66 69 6c 65 73 54 6f 74 61 6c 20 6f 66 20 52 41 4d 56 50 45 6e 74 69 74 79 31 32 4e } //1 autofillProfilesTotal of RAMVPEntity12N
		$a_81_3 = {77 69 6e 64 6f 77 73 2d 31 32 35 31 2c 20 43 6f 6d 6d 61 6e 64 4c 69 6e 65 } //1 windows-1251, CommandLine
		$a_81_4 = {52 65 70 6c 61 63 65 6c 75 65 6d 6f 7a 5f 63 6f 6f 6b 69 65 73 } //1 Replaceluemoz_cookies
		$a_81_5 = {6e 65 74 2e 74 63 70 3a 2f 2f } //1 net.tcp://
		$a_81_6 = {41 6e 74 69 46 69 6c 65 53 79 73 74 65 6d 53 70 79 57 46 69 6c 65 53 79 73 74 65 6d 61 72 65 50 72 6f 46 69 6c 65 53 79 73 74 65 6d 64 75 63 74 } //1 AntiFileSystemSpyWFileSystemareProFileSystemduct
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}
rule Trojan_BAT_RedLineStealer_EM_MTB_7{
	meta:
		description = "Trojan:BAT/RedLineStealer.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {47 6c 2e 68 33 2e 72 65 73 6f 75 72 63 65 73 } //1 Gl.h3.resources
		$a_01_1 = {50 69 63 74 75 72 65 47 61 6d 65 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 PictureGame.Resources.resources
		$a_01_2 = {61 52 33 6e 62 66 38 64 51 70 32 66 65 4c 6d 6b 33 31 2e 6c 53 66 67 41 70 61 74 6b 64 78 73 56 63 47 63 72 6b 74 6f 46 64 2e 72 65 73 6f 75 72 63 65 73 } //1 aR3nbf8dQp2feLmk31.lSfgApatkdxsVcGcrktoFd.resources
		$a_01_3 = {48 69 64 65 4d 6f 64 75 6c 65 4e 61 6d 65 41 74 74 72 69 62 75 74 65 } //1 HideModuleNameAttribute
		$a_01_4 = {48 65 6c 70 4b 65 79 77 6f 72 64 41 74 74 72 69 62 75 74 65 } //1 HelpKeywordAttribute
		$a_01_5 = {2f 00 63 00 20 00 72 00 6d 00 64 00 69 00 72 00 20 00 2f 00 51 00 20 00 2f 00 53 00 } //1 /c rmdir /Q /S
		$a_01_6 = {50 00 72 00 69 00 73 00 63 00 69 00 6c 00 6c 00 61 00 5f 00 54 00 61 00 79 00 6c 00 6f 00 72 00 } //1 Priscilla_Taylor
		$a_01_7 = {6d 00 4a 00 55 00 49 00 6e 00 58 00 } //1 mJUInX
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}