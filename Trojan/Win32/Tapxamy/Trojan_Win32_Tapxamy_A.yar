
rule Trojan_Win32_Tapxamy_A{
	meta:
		description = "Trojan:Win32/Tapxamy.A,SIGNATURE_TYPE_PEHSTR,1e 00 1e 00 03 00 00 0a 00 "
		
	strings :
		$a_01_0 = {50 59 47 2e 64 6c 6c } //0a 00  PYG.dll
		$a_01_1 = {6e 00 74 00 68 00 6f 00 6f 00 6b 00 2e 00 64 00 6c 00 6c 00 } //0a 00  nthook.dll
		$a_01_2 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 42 00 61 00 79 00 6d 00 61 00 78 00 50 00 61 00 74 00 63 00 68 00 54 00 6f 00 6f 00 6c 00 73 00 5c 00 49 00 6e 00 6a 00 65 00 63 00 74 00 44 00 6c 00 6c 00 } //00 00  Software\BaymaxPatchTools\InjectDll
		$a_01_3 = {00 67 16 00 00 59 c6 33 03 ee ff e3 38 25 e3 86 88 00 a6 17 00 01 20 50 fb 8d 5b 67 16 00 } //00 9d 
	condition:
		any of ($a_*)
 
}