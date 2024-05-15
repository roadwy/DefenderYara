
rule Trojan_Win64_Mikey_HNS_MTB{
	meta:
		description = "Trojan:Win64/Mikey.HNS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {4e 00 61 00 6d 00 65 00 00 00 00 00 4c 00 61 00 75 00 6e 00 63 00 68 00 65 00 72 00 00 00 00 00 3a 00 09 00 01 00 46 00 69 00 6c 00 65 00 44 00 65 00 73 00 63 00 72 00 69 00 70 00 74 00 69 00 6f 00 6e 00 00 00 00 00 4c 00 61 00 75 00 6e 00 63 00 68 00 65 00 72 00 } //02 00 
		$a_01_1 = {43 3a 5c 55 73 65 72 73 5c 6d 70 78 31 36 5c 73 6f 75 72 63 65 5c 72 65 70 6f 73 5c 4c 61 75 6e 63 68 65 72 5c 62 69 6e 5c 52 65 6c 65 61 73 65 5c 6e 65 74 38 2e 30 5c 77 69 6e 2d 78 36 34 5c 6e 61 74 69 76 65 5c 4c 61 75 6e 63 68 65 72 2e 70 64 62 } //00 00  C:\Users\mpx16\source\repos\Launcher\bin\Release\net8.0\win-x64\native\Launcher.pdb
	condition:
		any of ($a_*)
 
}