
rule Trojan_Win32_Farfli_TC_MTB{
	meta:
		description = "Trojan:Win32/Farfli.TC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {66 01 f0 46 ab 31 a1 90 01 04 17 87 e2 11 a0 90 01 04 04 ad a0 90 01 04 f2 f0 6c e2 85 74 dd 90 00 } //01 00 
		$a_03_1 = {31 27 ad 3d 90 01 04 f6 64 03 fe 10 5c d2 40 27 d2 36 90 00 } //02 00 
		$a_01_2 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //00 00 
	condition:
		any of ($a_*)
 
}