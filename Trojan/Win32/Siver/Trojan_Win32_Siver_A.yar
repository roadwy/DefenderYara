
rule Trojan_Win32_Siver_A{
	meta:
		description = "Trojan:Win32/Siver.A,SIGNATURE_TYPE_PEHSTR,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {4b 65 79 42 6f 61 72 64 64 6c 6c 2d } //01 00  KeyBoarddll-
		$a_01_1 = {4b 65 79 42 6f 61 72 64 2e 64 6c 6c } //01 00  KeyBoard.dll
		$a_01_2 = {53 65 61 72 63 68 64 6c 6c 2d } //01 00  Searchdll-
		$a_01_3 = {53 65 61 72 63 68 2e 64 6c 6c } //01 00  Search.dll
		$a_01_4 = {54 72 61 6e 73 69 74 64 6c 6c 2d } //01 00  Transitdll-
		$a_01_5 = {54 72 61 6e 73 69 74 2e 64 6c 6c } //01 00  Transit.dll
		$a_01_6 = {53 68 61 72 65 49 6e 66 65 63 74 64 6c 6c 2d } //01 00  ShareInfectdll-
		$a_01_7 = {53 68 61 72 65 49 6e 66 65 63 74 2e 64 6c 6c } //00 00  ShareInfect.dll
	condition:
		any of ($a_*)
 
}