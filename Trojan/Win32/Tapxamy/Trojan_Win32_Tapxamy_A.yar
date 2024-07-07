
rule Trojan_Win32_Tapxamy_A{
	meta:
		description = "Trojan:Win32/Tapxamy.A,SIGNATURE_TYPE_PEHSTR,1e 00 1e 00 03 00 00 "
		
	strings :
		$a_01_0 = {50 59 47 2e 64 6c 6c } //10 PYG.dll
		$a_01_1 = {6e 00 74 00 68 00 6f 00 6f 00 6b 00 2e 00 64 00 6c 00 6c 00 } //10 nthook.dll
		$a_01_2 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 42 00 61 00 79 00 6d 00 61 00 78 00 50 00 61 00 74 00 63 00 68 00 54 00 6f 00 6f 00 6c 00 73 00 5c 00 49 00 6e 00 6a 00 65 00 63 00 74 00 44 00 6c 00 6c 00 } //10 Software\BaymaxPatchTools\InjectDll
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10) >=30
 
}