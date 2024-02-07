
rule Trojan_Win32_Flaumy{
	meta:
		description = "Trojan:Win32/Flaumy,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 6d 64 20 2f 63 20 73 63 20 63 72 65 61 74 65 20 66 6f 75 6e 64 61 74 69 6f 6e 20 62 69 6e 70 61 74 68 3d } //01 00  cmd /c sc create foundation binpath=
		$a_01_1 = {5c 46 6f 75 6e 64 61 74 69 6f 6e 31 5c 77 6d 69 74 65 73 2e 65 78 65 } //01 00  \Foundation1\wmites.exe
		$a_01_2 = {62 75 6c 6c 67 75 61 72 64 2e 65 78 65 } //01 00  bullguard.exe
		$a_01_3 = {22 73 63 2e 65 78 65 22 20 64 65 6c 65 74 65 20 66 6f 75 6e 64 61 74 69 6f 6e 20 2f 79 } //00 00  "sc.exe" delete foundation /y
	condition:
		any of ($a_*)
 
}