
rule Trojan_Win32_Injuke_ABT_MTB{
	meta:
		description = "Trojan:Win32/Injuke.ABT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {33 18 89 1d 90 01 04 a1 90 01 04 8b 15 90 01 04 89 10 8b 45 f8 83 c0 04 89 45 f8 33 c0 a3 90 01 04 a1 90 01 04 83 c0 04 03 05 90 01 04 a3 90 01 04 8b 45 f8 3b 05 90 00 } //05 00 
		$a_01_1 = {32 32 79 6c 6b 75 38 79 68 30 34 39 79 75 30 33 34 68 6b 6f 66 77 34 32 68 34 72 79 6a 30 32 67 39 34 30 67 39 76 72 67 68 77 30 38 } //00 00 
	condition:
		any of ($a_*)
 
}