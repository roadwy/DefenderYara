
rule Trojan_Win32_Farfli_MG_MTB{
	meta:
		description = "Trojan:Win32/Farfli.MG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 05 00 "
		
	strings :
		$a_01_0 = {43 70 70 42 61 63 6b 64 6f 6f 72 5c 4c 6f 61 64 65 72 5c 52 65 6c 65 61 73 65 5c 4c 6f 61 64 65 72 2e 70 64 62 } //05 00  CppBackdoor\Loader\Release\Loader.pdb
		$a_01_1 = {51 51 51 51 51 51 51 51 51 51 51 51 51 51 51 51 51 51 51 51 51 51 51 51 01 14 51 51 1d 50 55 51 9b b6 ab 32 51 51 51 51 51 51 } //00 00 
	condition:
		any of ($a_*)
 
}