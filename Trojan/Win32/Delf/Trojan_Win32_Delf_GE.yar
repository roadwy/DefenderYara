
rule Trojan_Win32_Delf_GE{
	meta:
		description = "Trojan:Win32/Delf.GE,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //01 00  SOFTWARE\Borland\Delphi\RTL
		$a_01_1 = {6d 66 70 2e 62 66 7a 7a 2e 63 6f 6d 2f 6d 66 70 2f 64 6f 2e 61 73 70 } //01 00  mfp.bfzz.com/mfp/do.asp
		$a_01_2 = {3f 65 76 65 3d 67 65 74 26 75 73 65 72 6e 61 6d 65 3d } //01 00  ?eve=get&username=
		$a_01_3 = {53 6f 66 74 57 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //01 00  SoftWare\Microsoft\Windows\CurrentVersion\Run
		$a_01_4 = {44 45 4c 20 2f 61 20 22 } //00 00  DEL /a "
	condition:
		any of ($a_*)
 
}