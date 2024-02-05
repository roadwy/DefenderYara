
rule Trojan_Win32_Koutodoor_C_dll{
	meta:
		description = "Trojan:Win32/Koutodoor.C!dll,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {99 8b ce f7 f9 43 83 fb 04 } //02 00 
		$a_01_1 = {8a 45 14 32 c1 47 3b 7d 14 } //01 00 
		$a_01_2 = {39 33 34 38 2e 63 6e } //01 00 
		$a_01_3 = {33 32 39 41 36 32 34 41 2d 31 44 32 32 2d 34 38 61 65 2d 39 35 37 36 2d 41 30 32 46 31 45 44 42 31 33 37 32 } //00 00 
	condition:
		any of ($a_*)
 
}