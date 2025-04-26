
rule Trojan_Win32_Zenpack_EM_MTB{
	meta:
		description = "Trojan:Win32/Zenpack.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 e4 31 c9 89 c2 88 d3 8b 55 e8 88 1c 02 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
rule Trojan_Win32_Zenpack_EM_MTB_2{
	meta:
		description = "Trojan:Win32/Zenpack.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {c1 e0 04 89 01 c3 81 00 e1 34 ef c6 c3 01 08 c3 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
rule Trojan_Win32_Zenpack_EM_MTB_3{
	meta:
		description = "Trojan:Win32/Zenpack.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 20 b9 02 00 00 00 e2 11 4a 4a 89 e8 50 8f 05 ?? ?? ?? ?? e9 ?? ?? ?? ?? c3 42 83 c2 07 29 c2 8d 05 ?? ?? ?? ?? 31 38 83 e8 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
rule Trojan_Win32_Zenpack_EM_MTB_4{
	meta:
		description = "Trojan:Win32/Zenpack.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {83 ec 0c 89 e1 c7 41 04 8d 0c 00 00 c7 01 18 05 00 00 } //3
		$a_01_1 = {83 ec 04 88 44 24 1b e9 60 fb ff ff 8d 65 f8 5e 5f 5d c3 40 } //2
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}
rule Trojan_Win32_Zenpack_EM_MTB_5{
	meta:
		description = "Trojan:Win32/Zenpack.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {66 72 75 69 74 74 72 65 65 39 6f 77 6e } //1 fruittree9own
		$a_01_1 = {61 69 72 52 66 69 72 6d 61 6d 65 6e 74 5a } //1 airRfirmamentZ
		$a_01_2 = {74 68 69 6e 67 6b 66 6f 72 74 77 6f 64 65 65 70 73 74 61 72 73 4f 67 72 65 65 6e } //1 thingkfortwodeepstarsOgreen
		$a_01_3 = {47 6c 6f 62 61 6c 41 6c 6c 6f 63 } //1 GlobalAlloc
		$a_01_4 = {4c 6f 61 64 52 65 73 6f 75 72 63 65 } //1 LoadResource
		$a_01_5 = {44 65 76 69 63 65 49 6f 43 6f 6e 74 72 6f 6c } //1 DeviceIoControl
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}
rule Trojan_Win32_Zenpack_EM_MTB_6{
	meta:
		description = "Trojan:Win32/Zenpack.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {6c 6f 61 64 65 72 2e 63 70 70 2e 62 63 2e 6f 62 6a 2e 70 64 62 } //1 loader.cpp.bc.obj.pdb
		$a_81_1 = {64 6f 6d 69 6e 69 6f 6e 38 63 72 65 65 70 65 74 68 7a 48 69 73 6d 6f 76 65 64 46 69 73 68 67 47 } //1 dominion8creepethzHismovedFishgG
		$a_81_2 = {6f 6e 65 32 4b 74 77 6f 59 6f 75 2e 72 65 } //1 one2KtwoYou.re
		$a_81_3 = {52 65 70 6c 65 6e 69 73 68 4e 67 61 74 68 65 72 69 6e 67 } //1 ReplenishNgathering
		$a_81_4 = {43 72 65 61 74 65 50 6f 69 6e 74 65 72 4d 6f 6e 69 6b 65 72 } //1 CreatePointerMoniker
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}
rule Trojan_Win32_Zenpack_EM_MTB_7{
	meta:
		description = "Trojan:Win32/Zenpack.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {46 6f 72 2e 66 39 75 70 6f 6e 4e 53 66 6f 77 6c 73 6f 73 68 65 2e 64 47 72 65 61 74 65 72 } //1 For.f9uponNSfowlsoshe.dGreater
		$a_01_1 = {4d 61 6b 65 48 55 62 72 6f 75 67 68 74 66 69 73 68 } //1 MakeHUbroughtfish
		$a_01_2 = {68 65 61 76 65 6e 48 65 61 76 65 6e 6b 69 6e 64 43 45 6c 73 65 65 64 67 72 65 61 74 65 72 } //1 heavenHeavenkindCElseedgreater
		$a_01_3 = {66 65 6d 61 6c 65 6d 75 6c 74 69 70 6c 79 51 76 65 72 79 2c 31 32 63 55 66 } //1 femalemultiplyQvery,12cUf
		$a_01_4 = {63 61 6e 2e 74 63 72 65 61 74 65 64 2e 31 61 50 67 6f 6f 64 77 6f 6e 2e 74 49 6f 6a } //1 can.tcreated.1aPgoodwon.tIoj
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_Win32_Zenpack_EM_MTB_8{
	meta:
		description = "Trojan:Win32/Zenpack.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {68 66 6f 72 6d 64 72 79 41 69 73 6d 65 61 74 73 65 61 73 6f 6e 73 2e 74 68 69 72 64 42 } //1 hformdryAismeatseasons.thirdB
		$a_01_1 = {64 61 79 2e 6d 6f 76 69 6e 67 4f 46 72 6f 6d 65 51 74 68 65 79 6f 75 } //1 day.movingOFromeQtheyou
		$a_01_2 = {75 6d 6f 76 65 74 68 2e 73 61 79 69 6e 67 73 61 79 69 6e 67 } //1 umoveth.sayingsaying
		$a_01_3 = {77 61 73 64 61 79 68 65 72 62 2c 75 70 6f 6e 2e 65 61 72 74 68 6c 65 74 2e 4c 4c 63 72 65 65 70 65 74 68 6d 61 79 } //1 wasdayherb,upon.earthlet.LLcreepethmay
		$a_01_4 = {64 74 68 44 61 72 6b 6e 65 73 73 50 6c 69 33 65 76 65 6e 69 6e 67 2c 47 72 65 65 6e } //1 dthDarknessPli3evening,Green
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_Win32_Zenpack_EM_MTB_9{
	meta:
		description = "Trojan:Win32/Zenpack.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {73 00 65 00 74 00 62 00 65 00 68 00 6f 00 6c 00 64 00 2c 00 62 00 6c 00 65 00 73 00 73 00 65 00 64 00 59 00 6c 00 65 00 74 00 66 00 6c 00 79 00 61 00 62 00 75 00 6e 00 64 00 61 00 6e 00 74 00 6c 00 79 00 32 00 72 00 67 00 } //1 setbehold,blessedYletflyabundantly2rg
		$a_01_1 = {4c 00 69 00 67 00 68 00 74 00 79 00 4c 00 46 00 78 00 } //1 LightyLFx
		$a_01_2 = {74 00 68 00 65 00 69 00 72 00 2c 00 75 00 70 00 6f 00 6e 00 4b 00 69 00 73 00 6b 00 77 00 69 00 6e 00 67 00 65 00 64 00 37 00 75 00 70 00 6f 00 6e 00 } //1 their,uponKiskwinged7upon
		$a_01_3 = {4d 00 6f 00 66 00 53 00 75 00 62 00 64 00 75 00 65 00 6d 00 61 00 64 00 65 00 67 00 69 00 76 00 65 00 6e 00 68 00 } //1 MofSubduemadegivenh
		$a_01_4 = {54 00 45 00 53 00 54 00 41 00 50 00 50 00 2e 00 45 00 58 00 45 00 } //1 TESTAPP.EXE
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_Win32_Zenpack_EM_MTB_10{
	meta:
		description = "Trojan:Win32/Zenpack.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {56 00 68 00 62 00 65 00 67 00 69 00 6e 00 6e 00 69 00 6e 00 67 00 4b 00 66 00 35 00 73 00 65 00 61 00 73 00 61 00 79 00 69 00 6e 00 67 00 74 00 68 00 65 00 6d 00 } //1 VhbeginningKf5seasayingthem
		$a_01_1 = {38 00 58 00 4f 00 67 00 72 00 61 00 73 00 73 00 75 00 73 00 65 00 74 00 50 00 6c 00 61 00 63 00 65 00 } //1 8XOgrassusetPlace
		$a_01_2 = {58 00 66 00 61 00 63 00 65 00 75 00 6e 00 64 00 65 00 72 00 73 00 69 00 67 00 6e 00 73 00 2e 00 74 00 52 00 69 00 74 00 73 00 65 00 6c 00 66 00 33 00 44 00 6e 00 } //1 Xfaceundersigns.tRitself3Dn
		$a_01_3 = {30 00 63 00 61 00 6e 00 2e 00 74 00 30 00 66 00 69 00 72 00 6d 00 61 00 6d 00 65 00 6e 00 74 00 64 00 61 00 79 00 47 00 72 00 65 00 61 00 74 00 65 00 72 00 73 00 65 00 63 00 6f 00 6e 00 64 00 2c 00 63 00 72 00 65 00 65 00 70 00 69 00 6e 00 67 00 } //1 0can.t0firmamentdayGreatersecond,creeping
		$a_01_4 = {54 00 68 00 69 00 72 00 64 00 6d 00 6f 00 76 00 65 00 64 00 73 00 74 00 61 00 72 00 73 00 74 00 68 00 65 00 6d 00 } //1 Thirdmovedstarsthem
		$a_01_5 = {65 00 6d 00 6f 00 76 00 69 00 6e 00 67 00 62 00 63 00 72 00 65 00 65 00 70 00 69 00 6e 00 67 00 72 00 6d 00 61 00 79 00 72 00 6f 00 75 00 72 00 58 00 63 00 72 00 65 00 65 00 70 00 69 00 6e 00 67 00 } //1 emovingbcreepingrmayrourXcreeping
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}