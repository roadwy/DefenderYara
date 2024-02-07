
rule Trojan_Win64_BumbleBeeLoader_AG_MSR{
	meta:
		description = "Trojan:Win64/BumbleBeeLoader.AG!MSR,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {45 65 69 31 35 69 } //02 00  Eei15i
		$a_01_1 = {4c 69 52 4e 4e 35 46 } //02 00  LiRNN5F
		$a_01_2 = {58 5a 72 45 58 39 32 32 36 31 } //01 00  XZrEX92261
		$a_01_3 = {72 6f 6d 61 6e 74 69 63 20 6c 6f 66 74 79 20 6c 65 67 69 74 69 6d 61 74 65 20 64 69 73 74 72 61 63 74 } //01 00  romantic lofty legitimate distract
		$a_01_4 = {43 61 6c 6c 4e 61 6d 65 64 50 69 70 65 41 } //00 00  CallNamedPipeA
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_BumbleBeeLoader_AG_MSR_2{
	meta:
		description = "Trojan:Win64/BumbleBeeLoader.AG!MSR,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 07 00 00 02 00 "
		
	strings :
		$a_01_0 = {43 48 68 44 4a 43 4e } //02 00  CHhDJCN
		$a_01_1 = {44 77 44 44 42 53 36 35 6d } //02 00  DwDDBS65m
		$a_01_2 = {48 6c 4c 63 75 39 38 38 } //02 00  HlLcu988
		$a_01_3 = {50 52 69 31 36 53 45 } //02 00  PRi16SE
		$a_01_4 = {52 57 48 77 79 36 52 } //01 00  RWHwy6R
		$a_01_5 = {70 6f 6c 69 74 69 63 61 6c 20 64 65 62 72 69 73 20 79 65 6c 6c 20 63 6f 75 6c 64 20 71 75 69 76 65 72 } //01 00  political debris yell could quiver
		$a_01_6 = {43 72 65 61 74 65 4e 61 6d 65 64 50 69 70 65 41 } //00 00  CreateNamedPipeA
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_BumbleBeeLoader_AG_MSR_3{
	meta:
		description = "Trojan:Win64/BumbleBeeLoader.AG!MSR,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 02 00 "
		
	strings :
		$a_01_0 = {44 48 46 58 43 4d 39 50 71 } //02 00  DHFXCM9Pq
		$a_01_1 = {4c 66 74 59 6b } //02 00  LftYk
		$a_01_2 = {51 42 53 69 6a 70 7a 77 } //02 00  QBSijpzw
		$a_01_3 = {53 69 78 4f 35 30 37 31 44 } //02 00  SixO5071D
		$a_01_4 = {55 71 43 38 30 } //01 00  UqC80
		$a_01_5 = {74 6f 75 63 68 20 68 61 7a 65 20 68 61 6e 6b 79 20 73 63 75 6c 70 74 75 72 65 20 73 61 6e 63 74 69 6f 6e 20 72 61 67 20 68 6f 70 65 73 } //01 00  touch haze hanky sculpture sanction rag hopes
		$a_01_6 = {43 6f 6e 6e 65 63 74 4e 61 6d 65 64 50 69 70 65 } //01 00  ConnectNamedPipe
		$a_01_7 = {47 65 74 53 74 61 72 74 75 70 49 6e 66 6f 57 } //00 00  GetStartupInfoW
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_BumbleBeeLoader_AG_MSR_4{
	meta:
		description = "Trojan:Win64/BumbleBeeLoader.AG!MSR,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 07 00 00 02 00 "
		
	strings :
		$a_01_0 = {48 50 73 62 42 35 36 34 55 } //02 00  HPsbB564U
		$a_01_1 = {55 44 49 4f 63 4f 38 31 30 71 33 59 } //01 00  UDIOcO810q3Y
		$a_01_2 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //01 00  DllRegisterServer
		$a_01_3 = {63 6c 65 61 6e 75 70 20 73 70 6f 74 20 62 6f 64 69 6c 79 20 66 75 6c 66 69 6c 20 67 72 61 62 62 65 64 20 72 61 62 62 69 74 } //01 00  cleanup spot bodily fulfil grabbed rabbit
		$a_01_4 = {43 72 65 61 74 65 4e 61 6d 65 64 50 69 70 65 41 } //01 00  CreateNamedPipeA
		$a_01_5 = {50 65 65 6b 4e 61 6d 65 64 50 69 70 65 } //01 00  PeekNamedPipe
		$a_01_6 = {47 65 74 43 75 72 72 65 6e 74 44 69 72 65 63 74 6f 72 79 41 } //00 00  GetCurrentDirectoryA
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_BumbleBeeLoader_AG_MSR_5{
	meta:
		description = "Trojan:Win64/BumbleBeeLoader.AG!MSR,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 07 00 00 02 00 "
		
	strings :
		$a_01_0 = {4b 49 6e 4d 51 46 } //02 00  KInMQF
		$a_01_1 = {4b 77 4e 71 42 6e 32 6c 39 4e } //02 00  KwNqBn2l9N
		$a_01_2 = {53 72 4e 46 36 44 61 } //02 00  SrNF6Da
		$a_01_3 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //01 00  DllRegisterServer
		$a_01_4 = {62 75 73 69 6e 65 73 73 20 6f 76 65 72 6c 6f 6f 6b 20 64 75 6e 67 65 6f 6e 20 66 65 72 61 6c 20 66 6f 77 6c 73 20 73 70 69 64 65 72 73 20 72 61 74 65 20 66 72 6f 73 74 79 } //01 00  business overlook dungeon feral fowls spiders rate frosty
		$a_01_5 = {43 6f 6e 6e 65 63 74 4e 61 6d 65 64 50 69 70 65 } //01 00  ConnectNamedPipe
		$a_01_6 = {47 65 74 53 74 61 72 74 75 70 49 6e 66 6f 57 } //00 00  GetStartupInfoW
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_BumbleBeeLoader_AG_MSR_6{
	meta:
		description = "Trojan:Win64/BumbleBeeLoader.AG!MSR,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 09 00 00 02 00 "
		
	strings :
		$a_01_0 = {44 64 75 42 48 4f } //02 00  DduBHO
		$a_01_1 = {46 78 51 75 69 72 4c 32 } //02 00  FxQuirL2
		$a_01_2 = {4b 4e 4b 6d 74 74 68 49 6f } //02 00  KNKmtthIo
		$a_01_3 = {4b 73 6d 54 32 37 59 } //02 00  KsmT27Y
		$a_01_4 = {5a 57 66 4f 44 41 36 34 } //02 00  ZWfODA64
		$a_01_5 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //01 00  DllRegisterServer
		$a_01_6 = {68 61 72 64 77 6f 72 6b 69 6e 67 20 66 61 63 69 6e 67 20 63 6f 6e 63 65 6e 74 72 61 74 69 6f 6e 20 53 6f 75 74 68 20 61 6d 62 65 72 20 62 65 65 6e 20 73 61 66 65 74 79 20 66 6f 72 62 65 73 } //01 00  hardworking facing concentration South amber been safety forbes
		$a_01_7 = {43 61 6c 6c 4e 61 6d 65 64 50 69 70 65 41 } //01 00  CallNamedPipeA
		$a_01_8 = {47 65 74 53 74 61 72 74 75 70 49 6e 66 6f 57 } //00 00  GetStartupInfoW
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_BumbleBeeLoader_AG_MSR_7{
	meta:
		description = "Trojan:Win64/BumbleBeeLoader.AG!MSR,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 01 00 "
		
	strings :
		$a_01_0 = {4d 59 74 6c 32 4b } //01 00  MYtl2K
		$a_01_1 = {55 79 62 7a 77 47 72 } //01 00  UybzwGr
		$a_01_2 = {59 43 4e 45 4e 50 } //01 00  YCNENP
		$a_01_3 = {67 68 6a 67 6b 61 64 73 66 67 64 6a 67 68 } //01 00  ghjgkadsfgdjgh
		$a_01_4 = {69 76 59 69 77 32 } //01 00  ivYiw2
		$a_01_5 = {6c 69 42 45 46 61 33 51 71 62 } //01 00  liBEFa3Qqb
		$a_01_6 = {72 42 6e 31 4e 79 4f 73 6e 42 } //01 00  rBn1NyOsnB
		$a_01_7 = {74 4c 45 6d 59 61 38 } //01 00  tLEmYa8
		$a_01_8 = {78 68 70 68 6e 53 } //01 00  xhphnS
		$a_01_9 = {79 77 77 70 6b 43 } //01 00  ywwpkC
		$a_01_10 = {66 32 31 62 61 32 30 35 38 35 38 36 34 35 61 63 65 31 61 63 33 64 63 38 34 32 35 62 62 30 61 64 65 65 38 64 63 37 63 38 66 37 63 34 31 30 30 38 31 63 37 61 61 63 66 37 63 65 33 36 33 61 37 35 63 33 37 65 33 35 32 66 34 63 30 61 38 33 64 64 39 64 62 63 61 38 37 31 63 37 64 63 65 } //00 00  f21ba205858645ace1ac3dc8425bb0adee8dc7c8f7c410081c7aacf7ce363a75c37e352f4c0a83dd9dbca871c7dce
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_BumbleBeeLoader_AG_MSR_8{
	meta:
		description = "Trojan:Win64/BumbleBeeLoader.AG!MSR,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 01 00 "
		
	strings :
		$a_01_0 = {4b 49 6e 4d 51 46 } //01 00  KInMQF
		$a_01_1 = {4b 77 4e 71 42 6e 32 6c 39 4e } //01 00  KwNqBn2l9N
		$a_01_2 = {53 72 4e 46 36 44 61 } //01 00  SrNF6Da
		$a_01_3 = {4c 4c 42 4d 50 4d 55 73 71 66 } //01 00  LLBMPMUsqf
		$a_01_4 = {43 6f 6e 6e 65 63 74 4e 61 6d 65 64 50 69 70 65 } //01 00  ConnectNamedPipe
		$a_01_5 = {43 72 65 61 74 65 4e 61 6d 65 64 50 69 70 65 41 } //01 00  CreateNamedPipeA
		$a_01_6 = {57 61 69 74 4e 61 6d 65 64 50 69 70 65 41 } //01 00  WaitNamedPipeA
		$a_01_7 = {47 65 74 43 75 72 72 65 6e 74 41 63 74 43 74 78 } //01 00  GetCurrentActCtx
		$a_01_8 = {66 6f 77 6c 73 20 73 70 69 64 65 72 73 20 72 61 74 65 20 66 72 6f 73 74 79 20 63 6f 76 65 72 69 6e 67 20 62 72 75 74 61 6c 6c 79 20 6e 75 6d 65 72 61 6c 73 20 77 61 76 69 6e 67 20 68 75 67 65 20 77 65 64 67 65 20 62 72 6f 61 64 63 61 73 74 69 6e 67 20 66 69 6c 6c 20 63 6f 77 20 66 61 69 74 68 66 75 6c 20 69 6e 74 65 6c 6c 69 67 65 6e 74 } //00 00  fowls spiders rate frosty covering brutally numerals waving huge wedge broadcasting fill cow faithful intelligent
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_BumbleBeeLoader_AG_MSR_9{
	meta:
		description = "Trojan:Win64/BumbleBeeLoader.AG!MSR,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {4d 44 62 4a 76 56 61 4e 43 52 } //01 00  MDbJvVaNCR
		$a_01_1 = {47 65 74 50 72 6f 63 65 73 73 48 65 61 70 } //01 00  GetProcessHeap
		$a_01_2 = {47 65 74 53 74 61 72 74 75 70 49 6e 66 6f 57 } //01 00  GetStartupInfoW
		$a_01_3 = {49 6e 69 74 69 61 6c 69 7a 65 43 72 69 74 69 63 61 6c 53 65 63 74 69 6f 6e } //01 00  InitializeCriticalSection
		$a_01_4 = {45 6e 74 65 72 43 72 69 74 69 63 61 6c 53 65 63 74 69 6f 6e } //01 00  EnterCriticalSection
		$a_01_5 = {4c 65 61 76 65 43 72 69 74 69 63 61 6c 53 65 63 74 69 6f 6e } //02 00  LeaveCriticalSection
		$a_01_6 = {64 6f 75 67 68 20 73 68 69 6e 64 79 20 72 61 6c 70 68 20 62 72 75 73 68 65 64 20 77 6f 6c 66 20 62 65 68 61 6c 66 20 61 6e 73 77 65 72 65 64 20 63 69 74 79 20 72 65 61 72 65 64 20 72 65 63 72 75 69 74 20 73 75 66 66 69 63 69 65 6e 74 6c 79 20 63 6f 6e 73 74 65 6c 6c 61 74 69 6f 6e 20 73 6b 69 20 73 75 72 70 6c 75 73 20 72 65 6c 79 20 66 6f 67 67 79 20 73 70 61 72 72 6f 77 20 6f 79 73 74 65 72 20 70 75 72 73 75 69 74 20 69 6e 74 65 72 76 61 6c 20 42 69 62 6c 65 } //00 00  dough shindy ralph brushed wolf behalf answered city reared recruit sufficiently constellation ski surplus rely foggy sparrow oyster pursuit interval Bible
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_BumbleBeeLoader_AG_MSR_10{
	meta:
		description = "Trojan:Win64/BumbleBeeLoader.AG!MSR,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 12 00 00 03 00 "
		
	strings :
		$a_80_0 = {54 58 49 30 37 33 42 79 7a } //TXI073Byz  03 00 
		$a_80_1 = {45 64 48 56 6e 74 71 64 57 74 } //EdHVntqdWt  01 00 
		$a_80_2 = {50 65 65 6b 4e 61 6d 65 64 50 69 70 65 } //PeekNamedPipe  01 00 
		$a_80_3 = {43 72 65 61 74 65 4e 61 6d 65 64 50 69 70 65 41 } //CreateNamedPipeA  01 00 
		$a_80_4 = {47 65 74 43 6f 6d 70 75 74 65 72 4e 61 6d 65 41 } //GetComputerNameA  01 00 
		$a_80_5 = {47 65 74 53 74 61 72 74 75 70 49 6e 66 6f 57 } //GetStartupInfoW  01 00 
		$a_80_6 = {45 6e 74 65 72 43 72 69 74 69 63 61 6c 53 65 63 74 69 6f 6e } //EnterCriticalSection  01 00 
		$a_80_7 = {44 65 6c 65 74 65 43 72 69 74 69 63 61 6c 53 65 63 74 69 6f 6e } //DeleteCriticalSection  01 00 
		$a_80_8 = {47 65 74 50 72 6f 63 41 64 64 72 65 73 73 } //GetProcAddress  01 00 
		$a_80_9 = {4c 6f 61 64 4c 69 62 72 61 72 79 45 78 57 } //LoadLibraryExW  01 00 
		$a_80_10 = {47 65 74 43 75 72 72 65 6e 74 50 72 6f 63 65 73 73 } //GetCurrentProcess  01 00 
		$a_80_11 = {54 65 72 6d 69 6e 61 74 65 50 72 6f 63 65 73 73 } //TerminateProcess  01 00 
		$a_80_12 = {47 65 74 45 6e 76 69 72 6f 6e 6d 65 6e 74 53 74 72 69 6e 67 73 57 } //GetEnvironmentStringsW  01 00 
		$a_80_13 = {57 72 69 74 65 46 69 6c 65 } //WriteFile  01 00 
		$a_80_14 = {47 65 74 50 72 6f 63 65 73 73 48 65 61 70 } //GetProcessHeap  01 00 
		$a_80_15 = {48 65 61 70 41 6c 6c 6f 63 } //HeapAlloc  01 00 
		$a_80_16 = {47 65 74 4d 6f 64 75 6c 65 46 69 6c 65 4e 61 6d 65 41 } //GetModuleFileNameA  01 00 
		$a_80_17 = {43 72 65 61 74 65 46 69 6c 65 57 } //CreateFileW  00 00 
	condition:
		any of ($a_*)
 
}