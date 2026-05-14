
rule Trojan_Win32_Fragtor_ARR_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 03 00 00 "
		
	strings :
		$a_81_0 = {4c 6f 61 64 6d 79 44 6c 6c } //6 LoadmyDll
		$a_81_1 = {73 74 72 61 74 20 72 75 6e } //4 strat run
		$a_81_2 = {49 4f 4a 43 4d 61 69 6e } //10 IOJCMain
	condition:
		((#a_81_0  & 1)*6+(#a_81_1  & 1)*4+(#a_81_2  & 1)*10) >=20
 
}
rule Trojan_Win32_Fragtor_ARR_MTB_2{
	meta:
		description = "Trojan:Win32/Fragtor.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 03 00 00 "
		
	strings :
		$a_01_0 = {8a 14 06 30 14 39 47 3b 7d 0c 72 } //10
		$a_81_1 = {72 4a 68 37 36 64 41 64 35 5a 59 68 4e 51 74 38 37 5a 51 56 45 76 41 77 } //8 rJh76dAd5ZYhNQt87ZQVEvAw
		$a_81_2 = {73 64 73 64 70 6c 2e 65 78 65 } //2 sdsdpl.exe
	condition:
		((#a_01_0  & 1)*10+(#a_81_1  & 1)*8+(#a_81_2  & 1)*2) >=20
 
}
rule Trojan_Win32_Fragtor_ARR_MTB_3{
	meta:
		description = "Trojan:Win32/Fragtor.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f 57 c8 66 0f 6e c0 66 0f 7e 09 66 0f 70 c8 ?? 66 0f fe cb 66 0f 6e c2 0f 54 ca } //6
		$a_01_1 = {66 0f fe cd 66 0f 6e c7 0f 54 cc 66 0f 7e 1a 66 0f 67 c9 66 0f 67 c9 0f 57 c8 } //4
	condition:
		((#a_03_0  & 1)*6+(#a_01_1  & 1)*4) >=10
 
}
rule Trojan_Win32_Fragtor_ARR_MTB_4{
	meta:
		description = "Trojan:Win32/Fragtor.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b6 c2 03 c8 0f b6 c1 8a 84 05 fc fe ff ff 30 04 3e 46 8b 85 f4 fe ff ff 3b f3 } //12
		$a_03_1 = {0f b6 ca 03 c8 0f b6 c9 89 8d ?? ?? ?? ?? 8a 04 0e 88 03 43 83 ad ?? ?? ?? ?? ?? 88 14 0e 75 } //8
	condition:
		((#a_01_0  & 1)*12+(#a_03_1  & 1)*8) >=20
 
}
rule Trojan_Win32_Fragtor_ARR_MTB_5{
	meta:
		description = "Trojan:Win32/Fragtor.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b cb 8d 55 d4 2b c8 be ?? ?? ?? ?? 3b ce 0f 42 f1 83 7d } //18
		$a_81_1 = {30 4a 65 77 66 33 33 34 77 65 72 66 35 32 44 4b 34 38 39 53 45 56 35 36 37 45 46 47 46 44 47 77 59 5a 73 64 66 65 57 52 74 4e 64 31 32 33 41 42 43 65 75 76 77 7a } //2 0Jewf334werf52DK489SEV567EFGFDGwYZsdfeWRtNd123ABCeuvwz
	condition:
		((#a_03_0  & 1)*18+(#a_81_1  & 1)*2) >=20
 
}
rule Trojan_Win32_Fragtor_ARR_MTB_6{
	meta:
		description = "Trojan:Win32/Fragtor.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a cb f6 d1 32 cb 80 e1 ?? 32 d9 8d 55 } //10
		$a_01_1 = {4a 00 4a 00 56 00 31 00 33 00 4a 00 33 00 54 00 71 00 51 00 4e 00 6a 00 39 00 34 00 50 00 76 00 30 00 36 00 39 00 4b 00 77 00 61 00 6c 00 46 00 33 00 69 00 5a 00 76 00 44 00 39 00 38 } //20
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*20) >=30
 
}
rule Trojan_Win32_Fragtor_ARR_MTB_7{
	meta:
		description = "Trojan:Win32/Fragtor.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 04 00 00 "
		
	strings :
		$a_03_0 = {0f 10 23 0f 10 6b ?? 0f 57 e0 0f 57 e9 0f 11 20 0f 11 68 } //8
		$a_03_1 = {f7 e1 8d 8e ?? ?? ?? ?? 89 d0 89 fa d1 e8 66 83 7e } //6
		$a_03_2 = {f7 e1 8b 46 ?? 89 d7 89 c1 f7 66 } //4
		$a_81_3 = {46 72 6f 6d 55 74 66 38 45 72 72 6f 72 62 79 74 65 73 4e 75 6c 4d 75 74 65 78 45 72 72 6f 72 7e 5c 2e 63 61 72 67 6f 5c 72 65 67 69 73 74 72 79 5c 73 72 63 5c 69 6e 64 65 78 2e 63 72 61 74 65 73 2e 69 6f 2d 31 39 34 39 63 66 38 63 36 62 35 62 35 35 37 66 } //2 FromUtf8ErrorbytesNulMutexError~\.cargo\registry\src\index.crates.io-1949cf8c6b5b557f
	condition:
		((#a_03_0  & 1)*8+(#a_03_1  & 1)*6+(#a_03_2  & 1)*4+(#a_81_3  & 1)*2) >=20
 
}