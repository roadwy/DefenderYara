
rule Trojan_Win32_Spyload_A{
	meta:
		description = "Trojan:Win32/Spyload.A,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {79 73 70 79 6c 6f 61 64 65 72 2e 64 6c 6c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 } //01 00  獹祰潬摡牥搮汬䐀汬慃啮汮慯乤睯
		$a_01_1 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //01 00  SOFTWARE\Borland\Delphi\RTL
		$a_01_2 = {6d 65 68 72 64 61 64 2e 64 61 74 } //01 00  mehrdad.dat
		$a_01_3 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 53 68 65 6c 6c 20 46 6f 6c 64 65 72 73 00 } //00 00 
	condition:
		any of ($a_*)
 
}