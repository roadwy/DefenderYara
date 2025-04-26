
rule Trojan_Win64_ZetaNile_N_dha{
	meta:
		description = "Trojan:Win64/ZetaNile.N!dha,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {34 34 2e 32 33 38 2e 37 34 2e 38 34 } //1 44.238.74.84
		$a_01_1 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 54 00 69 00 67 00 68 00 74 00 56 00 4e 00 43 00 5c 00 56 00 69 00 65 00 77 00 65 00 72 00 } //1 Software\TightVNC\Viewer
		$a_01_2 = {77 00 2d 00 61 00 64 00 61 00 2e 00 61 00 6d 00 61 00 7a 00 6f 00 6e 00 61 00 77 00 73 00 } //1 w-ada.amazonaws
		$a_01_3 = {32 2e 4d 79 44 65 76 65 6c 6f 70 6d 65 6e 74 5c 33 2e 54 6f 6f 6c 73 5f 44 65 76 65 6c 6f 70 6d 65 6e 74 5c 34 2e 54 69 67 68 74 56 4e 43 43 75 73 74 6f 6d 69 7a 65 5c 4d 75 6e 6e 61 5f 43 75 73 74 6f 6d 69 7a 65 5c 74 69 67 68 74 76 6e 63 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 74 76 6e 76 69 65 77 65 72 2e 70 64 62 } //1 2.MyDevelopment\3.Tools_Development\4.TightVNCCustomize\Munna_Customize\tightvnc\x64\Release\tvnviewer.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}