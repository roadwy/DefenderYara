
rule Trojan_Win32_Srendiv_A{
	meta:
		description = "Trojan:Win32/Srendiv.A,SIGNATURE_TYPE_PEHSTR,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 63 6c 69 65 6e 74 5f 72 65 67 69 73 74 65 72 5f 61 76 2e 64 6f 3f 25 73 25 64 26 76 65 72 3d 25 2e 32 66 26 61 76 65 72 3d 25 2e 32 66 26 25 73 3d 25 73 } //01 00  /client_register_av.do?%s%d&ver=%.2f&aver=%.2f&%s=%s
		$a_01_1 = {6d 6e 6d 73 72 76 63 00 2d 70 00 00 6d 73 72 76 63 } //01 00 
		$a_01_2 = {25 73 5c 64 72 69 76 65 72 73 5c 25 73 25 73 } //01 00  %s\drivers\%s%s
		$a_01_3 = {5c 25 30 38 78 2e 65 78 65 } //01 00  \%08x.exe
		$a_01_4 = {57 69 6e 64 6f 77 73 20 46 69 6c 65 20 50 72 6f 74 65 63 74 69 6f 6e } //01 00  Windows File Protection
		$a_01_5 = {5a 77 43 72 65 61 74 65 50 72 6f 63 65 73 73 } //01 00  ZwCreateProcess
		$a_01_6 = {25 73 20 2d 73 65 6c 66 } //00 00  %s -self
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Srendiv_A_2{
	meta:
		description = "Trojan:Win32/Srendiv.A,SIGNATURE_TYPE_PEHSTR,21 00 21 00 09 00 00 0a 00 "
		
	strings :
		$a_01_0 = {2f 63 6c 69 65 6e 74 5f 72 65 67 69 73 74 65 72 5f 61 76 2e 64 6f 3f 25 73 25 64 26 76 65 72 3d 25 2e 32 66 26 61 76 65 72 3d 25 2e 32 66 26 25 73 3d 25 73 } //0a 00  /client_register_av.do?%s%d&ver=%.2f&aver=%.2f&%s=%s
		$a_01_1 = {5c 25 30 38 78 2e 65 78 65 } //0a 00  \%08x.exe
		$a_01_2 = {57 69 6e 64 6f 77 73 20 46 69 6c 65 20 50 72 6f 74 65 63 74 69 6f 6e } //01 00  Windows File Protection
		$a_01_3 = {5f 4c 69 76 65 55 70 64 61 74 65 } //01 00  _LiveUpdate
		$a_01_4 = {30 44 32 41 34 30 31 45 2d 33 45 39 46 2d 34 65 32 35 2d 42 30 33 35 2d 34 42 30 31 46 44 45 42 44 38 35 44 } //01 00  0D2A401E-3E9F-4e25-B035-4B01FDEBD85D
		$a_01_5 = {47 6f 6f 67 6c 65 55 70 64 61 74 65 72 53 65 72 76 69 63 65 2e 65 78 65 } //01 00  GoogleUpdaterService.exe
		$a_01_6 = {4f 53 45 2e 45 58 45 } //01 00  OSE.EXE
		$a_01_7 = {26 75 5f 6e 61 6d 65 3d } //01 00  &u_name=
		$a_01_8 = {73 74 6f 72 6d 6c 69 76 2e 65 78 65 } //00 00  stormliv.exe
	condition:
		any of ($a_*)
 
}