
rule Trojan_Win32_VB{
	meta:
		description = "Trojan:Win32/VB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {45 6e 63 72 69 70 74 61 41 50 49 } //01 00  EncriptaAPI
		$a_01_1 = {53 74 75 62 64 6f 73 } //01 00  Stubdos
		$a_01_2 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 33 32 5c 77 65 77 65 77 65 65 65 2e 64 6c 6c } //01 00  C:\WINDOWS\system32\weweweee.dll
		$a_01_3 = {76 62 61 73 73 73 73 73 72 43 6f 70 79 } //00 00  vbasssssrCopy
	condition:
		any of ($a_*)
 
}