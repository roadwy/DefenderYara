
rule Trojan_Win32_Jorik_MA_MTB{
	meta:
		description = "Trojan:Win32/Jorik.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {31 32 34 30 32 33 2d 35 39 32 2d 31 32 33 3d 31 32 2d 33 34 2d 32 33 30 34 2d 3d 32 33 30 35 00 2e 00 00 00 00 01 00 12 00 9c e3 40 } //01 00 
		$a_01_1 = {f4 01 00 00 9c e3 40 00 00 00 00 00 80 19 42 00 e0 81 45 00 e8 74 00 00 08 90 45 00 f6 50 40 00 00 90 45 } //00 00 
	condition:
		any of ($a_*)
 
}