
rule Trojan_Win32_FavLoader_A_MTB{
	meta:
		description = "Trojan:Win32/FavLoader.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {72 75 6e 64 6c 6c 33 32 20 66 61 76 69 63 6f 6e 2e 6a 70 67 2c 20 23 } //01 00 
		$a_01_1 = {57 69 6e 45 78 65 63 } //01 00 
		$a_01_2 = {43 72 65 61 74 65 4d 75 74 65 78 } //00 00 
	condition:
		any of ($a_*)
 
}