
rule Trojan_BAT_Crysan_AD_MTB{
	meta:
		description = "Trojan:BAT/Crysan.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 03 00 "
		
	strings :
		$a_80_0 = {51 32 78 70 5a 57 35 30 58 79 51 3d } //Q2xpZW50XyQ=  03 00 
		$a_80_1 = {32 32 35 2e 32 32 2e 32 36 2e 33 35 } //225.22.26.35  03 00 
		$a_80_2 = {41 73 73 65 6d } //Assem  03 00 
		$a_80_3 = {43 68 65 63 6b 48 6f 73 74 4e 61 6d 65 } //CheckHostName  03 00 
		$a_80_4 = {67 65 74 5f 4f 53 46 75 6c 6c 4e 61 6d 65 } //get_OSFullName  03 00 
		$a_80_5 = {44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 } //DownloadString  03 00 
		$a_80_6 = {73 65 74 5f 55 73 65 53 68 65 6c 6c 45 78 65 63 75 74 65 } //set_UseShellExecute  00 00 
	condition:
		any of ($a_*)
 
}