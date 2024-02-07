
rule Trojan_Win64_Strilix_C_dha{
	meta:
		description = "Trojan:Win64/Strilix.C!dha,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 04 00 "
		
	strings :
		$a_03_0 = {53 65 72 76 69 63 65 4d 61 69 6e 90 02 08 52 74 6c 44 65 63 6f 6d 70 72 65 73 73 42 75 66 43 72 79 70 74 53 74 72 69 6e 67 54 6f 42 69 6e 90 00 } //02 00 
		$a_01_1 = {63 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 70 72 69 6e 74 68 65 6c 70 2e 64 61 74 } //02 00  c:\windows\system32\printhelp.dat
		$a_01_2 = {63 3a 5c 77 69 6e 64 6f 77 73 5c 61 70 70 68 65 6c 70 2e 64 6c 6c } //00 00  c:\windows\apphelp.dll
	condition:
		any of ($a_*)
 
}