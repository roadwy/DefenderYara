
rule Trojan_Win32_Refams_A{
	meta:
		description = "Trojan:Win32/Refams.A,SIGNATURE_TYPE_PEHSTR,1e 00 1e 00 03 00 00 0a 00 "
		
	strings :
		$a_01_0 = {40 00 2a 00 5c 00 41 00 45 00 3a 00 5c 00 52 00 45 00 39 00 46 00 41 00 33 00 7e 00 31 00 5c 00 42 00 55 00 47 00 5f 00 31 00 5f 00 7e 00 31 00 5c 00 58 00 58 00 58 00 58 00 58 00 58 00 7e 00 31 00 2e 00 56 00 42 00 50 00 } //0a 00  @*\AE:\RE9FA3~1\BUG_1_~1\XXXXXX~1.VBP
		$a_01_1 = {5c 00 64 00 6c 00 6c 00 63 00 61 00 63 00 68 00 65 00 5c 00 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 5f 00 46 00 69 00 6c 00 65 00 5c 00 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 5f 00 46 00 69 00 6c 00 65 00 5c 00 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 5f 00 46 00 69 00 6c 00 65 00 5c 00 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 5f 00 46 00 69 00 6c 00 65 00 5c 00 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 5f 00 46 00 69 00 6c 00 65 00 } //0a 00  \dllcache\Download_File\Download_File\Download_File\Download_File\Download_File
		$a_01_2 = {43 61 6e 20 59 6f 75 20 74 68 69 73 20 69 73 20 50 72 6f 67 72 61 6d 20 46 69 6c 65 20 52 65 6d 6f 76 65 } //00 00  Can You this is Program File Remove
	condition:
		any of ($a_*)
 
}