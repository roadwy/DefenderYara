
rule Trojan_Win32_SpywareX_CRDB_MTB{
	meta:
		description = "Trojan:Win32/SpywareX.CRDB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {62 56 6c 57 54 56 31 48 45 77 63 3d } //01 00 
		$a_01_1 = {65 6e 63 72 79 70 74 65 64 5f 6b 65 79 } //01 00 
		$a_01_2 = {62 57 42 63 56 51 4d 41 47 51 49 36 4c 6b 46 48 51 55 51 43 44 43 73 45 42 57 4e 65 52 31 31 41 48 55 63 50 43 41 6f 3d } //01 00 
		$a_01_3 = {68 74 74 70 3a 2f 2f 39 34 2e 31 34 32 2e 31 33 38 2e 39 37 2f 55 70 } //00 00 
	condition:
		any of ($a_*)
 
}