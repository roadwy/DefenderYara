
rule Trojan_Win32_Dialer_SG_MTB{
	meta:
		description = "Trojan:Win32/Dialer.SG!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 6e 65 77 64 69 61 6c 65 72 2e 65 78 65 } //01 00  \newdialer.exe
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 54 72 69 6e 69 74 79 46 4c 41 } //01 00  Software\TrinityFLA
		$a_01_2 = {5c 75 6e 73 69 7a 7a 6c 65 2e 62 61 74 } //00 00  \unsizzle.bat
	condition:
		any of ($a_*)
 
}