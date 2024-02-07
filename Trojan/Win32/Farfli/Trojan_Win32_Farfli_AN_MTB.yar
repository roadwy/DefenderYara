
rule Trojan_Win32_Farfli_AN_MTB{
	meta:
		description = "Trojan:Win32/Farfli.AN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {89 45 e4 3d 00 01 00 00 7d 10 8a 88 90 02 04 88 8c 30 90 02 04 40 eb e6 90 00 } //01 00 
		$a_01_1 = {71 6b 6a 6f 67 69 6a 61 6c 6b 2e 65 78 65 } //01 00  qkjogijalk.exe
		$a_01_2 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //01 00  VirtualProtect
		$a_01_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //00 00  VirtualAlloc
	condition:
		any of ($a_*)
 
}