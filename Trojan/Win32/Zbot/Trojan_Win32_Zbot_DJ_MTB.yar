
rule Trojan_Win32_Zbot_DJ_MTB{
	meta:
		description = "Trojan:Win32/Zbot.DJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {43 3a 5c 55 73 65 72 73 5c 61 64 6d 69 6e 5c 44 6f 77 6e 6c 6f 61 64 73 5c 68 63 62 6e 61 66 2e 65 78 65 } //01 00  C:\Users\admin\Downloads\hcbnaf.exe
		$a_81_1 = {43 3a 5c 55 73 65 72 73 5c 73 68 65 6c 6c 79 5c 41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 54 65 6d 70 5c 66 69 6c 65 2e 65 78 65 } //01 00  C:\Users\shelly\AppData\Local\Temp\file.exe
		$a_81_2 = {74 75 65 32 37 2e 65 78 65 } //01 00  tue27.exe
		$a_81_3 = {63 61 72 64 69 66 66 70 6f 77 65 72 2e 63 6f 6d } //01 00  cardiffpower.com
		$a_81_4 = {55 70 64 61 74 65 73 20 64 6f 77 6e 6c 6f 61 64 65 72 } //00 00  Updates downloader
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Zbot_DJ_MTB_2{
	meta:
		description = "Trojan:Win32/Zbot.DJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {71 66 46 34 34 44 50 4f 56 4c 55 6d 79 6f 64 4b 78 34 70 67 6a 56 44 78 32 75 42 69 6b 57 41 71 62 38 52 51 37 4e 4c 6c 34 36 7a 75 44 42 62 4b } //01 00  qfF44DPOVLUmyodKx4pgjVDx2uBikWAqb8RQ7NLl46zuDBbK
		$a_01_1 = {7a 62 67 65 48 33 34 52 55 73 6a 4e 75 4c 34 61 70 71 77 6e 43 56 52 68 74 55 77 62 78 56 53 48 4c 6f 4e 6a 63 72 38 70 4c 67 77 6b 37 31 79 79 54 4c 54 33 44 6f 6b 45 64 69 63 55 32 78 56 78 75 68 63 34 4b 6b 69 4f 70 39 50 36 6b 4e } //01 00  zbgeH34RUsjNuL4apqwnCVRhtUwbxVSHLoNjcr8pLgwk71yyTLT3DokEdicU2xVxuhc4KkiOp9P6kN
		$a_01_2 = {33 66 76 47 54 56 42 76 4d 4f 6f 46 72 49 44 72 4c 70 30 34 51 68 31 76 76 58 69 79 52 57 4d 39 33 50 4f 46 5a 79 39 34 48 36 39 37 4e 45 43 38 4d 4b 62 4d 4f 6f 44 79 31 62 35 55 44 75 6d 74 57 48 64 4c 5a 72 79 58 54 4e 4a 61 67 6c } //01 00  3fvGTVBvMOoFrIDrLp04Qh1vvXiyRWM93POFZy94H697NEC8MKbMOoDy1b5UDumtWHdLZryXTNJagl
		$a_01_3 = {34 4b 4f 4b 6e 48 6f 53 73 49 59 70 39 50 67 45 45 4e 6f 5a 31 50 69 37 31 73 71 69 36 32 45 69 74 42 32 44 48 6e 70 77 39 50 54 30 66 52 70 45 42 35 38 4d 45 41 63 62 41 78 64 53 6a 55 59 66 78 } //01 00  4KOKnHoSsIYp9PgEENoZ1Pi71sqi62EitB2DHnpw9PT0fRpEB58MEAcbAxdSjUYfx
		$a_01_4 = {73 47 36 74 75 7a 53 55 41 4b 4e 4d 32 48 34 4e 74 31 45 31 76 72 4e 68 72 6b 4f 67 71 6b 52 36 7a 6f 68 59 38 68 4f 5a 42 4e 4c 63 4b 58 6d 68 47 4d 76 6f 6e 30 4a 38 44 55 32 57 76 } //00 00  sG6tuzSUAKNM2H4Nt1E1vrNhrkOgqkR6zohY8hOZBNLcKXmhGMvon0J8DU2Wv
	condition:
		any of ($a_*)
 
}