
rule Trojan_Win32_ZetaNile_M_dha{
	meta:
		description = "Trojan:Win32/ZetaNile.M!dha,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {49 53 53 65 74 75 70 50 72 65 72 65 71 75 69 73 69 74 65 73 5c 73 65 74 75 70 36 34 2e 65 78 65 } //01 00 
		$a_01_1 = {63 3a 5c 63 6f 6c 6f 72 63 74 72 6c 5c 63 6f 6c 6f 72 75 69 2e 64 6c 6c } //01 00 
		$a_01_2 = {63 3a 5c 63 6f 6c 6f 72 63 74 72 6c 5c 63 6f 6c 6f 72 63 70 6c 2e 65 78 65 20 43 33 41 39 42 33 30 42 36 41 33 31 33 46 32 38 39 32 39 37 43 39 41 33 36 37 33 30 44 42 36 44 } //00 00 
	condition:
		any of ($a_*)
 
}