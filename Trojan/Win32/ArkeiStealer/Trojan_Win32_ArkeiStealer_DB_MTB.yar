
rule Trojan_Win32_ArkeiStealer_DB_MTB{
	meta:
		description = "Trojan:Win32/ArkeiStealer.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 06 00 00 03 00 "
		
	strings :
		$a_80_0 = {31 32 35 34 37 38 38 32 34 35 31 35 41 44 4e 78 75 32 63 63 62 77 65 } //125478824515ADNxu2ccbwe  03 00 
		$a_80_1 = {6d 73 67 3d 4e 6f 2d 45 78 65 73 2d 46 6f 75 6e 64 2d 54 6f 2d 52 75 6e } //msg=No-Exes-Found-To-Run  03 00 
		$a_80_2 = {26 69 70 3d 26 6f 69 64 3d 31 33 39 } //&ip=&oid=139  03 00 
		$a_80_3 = {2f 64 65 76 2f 72 61 6e 64 6f 6d } ///dev/random  03 00 
		$a_80_4 = {70 74 68 72 65 61 64 5f 6d 75 74 65 78 5f 75 6e 6c 6f 63 6b } //pthread_mutex_unlock  03 00 
		$a_80_5 = {70 74 68 72 65 61 64 5f 63 6f 6e 64 5f 62 72 6f 61 64 63 61 73 74 } //pthread_cond_broadcast  00 00 
	condition:
		any of ($a_*)
 
}