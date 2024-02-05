
rule Trojan_Win32_DarkWatchman_EZ_MTB{
	meta:
		description = "Trojan:Win32/DarkWatchman.EZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 05 00 00 0a 00 "
		
	strings :
		$a_01_0 = {3a 00 3a 00 20 00 43 00 6c 00 69 00 70 00 62 00 6f 00 61 00 72 00 64 00 } //01 00 
		$a_01_1 = {6a 33 34 33 61 37 65 34 64 } //02 00 
		$a_01_2 = {64 33 62 37 31 37 35 62 39 } //01 00 
		$a_01_3 = {61 37 36 30 37 36 32 31 30 } //02 00 
		$a_01_4 = {67 31 65 33 32 61 61 61 34 } //00 00 
	condition:
		any of ($a_*)
 
}