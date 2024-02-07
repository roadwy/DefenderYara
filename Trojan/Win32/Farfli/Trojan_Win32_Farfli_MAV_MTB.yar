
rule Trojan_Win32_Farfli_MAV_MTB{
	meta:
		description = "Trojan:Win32/Farfli.MAV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 05 00 00 05 00 "
		
	strings :
		$a_01_0 = {55 6b 52 5a 58 42 52 61 46 56 39 57 57 79 73 3d } //05 00  UkRZXBRaFV9WWys=
		$a_01_1 = {5c 41 32 5c 52 65 6c 65 61 73 65 5c 41 32 2e 70 64 62 } //05 00  \A2\Release\A2.pdb
		$a_01_2 = {53 48 45 4c 4c 43 4f 44 45 } //05 00  SHELLCODE
		$a_01_3 = {43 3a 2f 2f 50 72 6f 67 72 61 6d 44 61 74 61 2f 2f 7a 7a 7a 7a 7a 7a 7a 7a 7a 7a 7a 7a 7a 7a 7a 7a 7a 7a 7a 7a 7a 7a 7a 7a 7a 7a 7a 7a 7a 7a 7a 7a 7a 7a 7a 7a 7a 7a 7a 7a } //01 00  C://ProgramData//zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz
		$a_01_4 = {51 75 65 72 79 50 65 72 66 6f 72 6d 61 6e 63 65 43 6f 75 6e 74 65 72 } //00 00  QueryPerformanceCounter
	condition:
		any of ($a_*)
 
}