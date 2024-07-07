
rule Worm_Win32_Siver_A_dll{
	meta:
		description = "Worm:Win32/Siver.A!dll,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {4b 65 79 42 6f 61 72 64 64 6c 6c 2d } //1 KeyBoarddll-
		$a_01_1 = {53 65 61 72 63 68 64 6c 6c 2d } //1 Searchdll-
		$a_01_2 = {54 72 61 6e 73 69 74 64 6c 6c 2d } //1 Transitdll-
		$a_01_3 = {53 68 61 72 65 49 6e 66 65 63 74 64 6c 6c 2d } //1 ShareInfectdll-
		$a_01_4 = {5b 41 75 74 6f 52 75 6e 5d } //1 [AutoRun]
		$a_01_5 = {3a 5c 41 75 74 6f 52 75 6e 2e 69 6e 66 } //1 :\AutoRun.inf
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}