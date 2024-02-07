
rule Trojan_Win32_Killfiles_RZ{
	meta:
		description = "Trojan:Win32/Killfiles.RZ,SIGNATURE_TYPE_PEHSTR,0b 00 0b 00 05 00 00 04 00 "
		
	strings :
		$a_01_0 = {5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 72 65 6d 6f 76 65 67 62 2e 73 79 73 } //04 00  \windows\system32\removegb.sys
		$a_01_1 = {44 52 56 20 52 20 47 42 00 00 00 00 72 65 6d 6f 76 65 67 62 } //03 00 
		$a_01_2 = {4d 69 63 72 6f 73 6f 66 74 4e 45 54 } //03 00  MicrosoftNET
		$a_01_3 = {63 00 72 00 65 00 64 00 69 00 63 00 61 00 72 00 64 00 69 00 74 00 61 00 75 00 2e 00 63 00 6f 00 6d 00 2e 00 62 00 72 00 } //03 00  credicarditau.com.br
		$a_01_4 = {20 43 2d 41 2d 52 2d 44 2d 53 20 2d 20 49 2d 54 2d 41 2d } //00 00   C-A-R-D-S - I-T-A-
	condition:
		any of ($a_*)
 
}