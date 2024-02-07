
rule Trojan_Win32_Urelas_K{
	meta:
		description = "Trojan:Win32/Urelas.K,SIGNATURE_TYPE_PEHSTR_EXT,1f 00 1f 00 05 00 00 0a 00 "
		
	strings :
		$a_01_0 = {67 00 6f 00 6c 00 66 00 69 00 6e 00 66 00 6f 00 2e 00 69 00 6e 00 69 00 } //0a 00  golfinfo.ini
		$a_01_1 = {5f 00 75 00 6e 00 69 00 6e 00 73 00 65 00 70 00 2e 00 62 00 61 00 74 00 } //0a 00  _uninsep.bat
		$a_01_2 = {73 00 79 00 73 00 74 00 65 00 6d 00 6b 00 65 00 79 00 } //01 00  systemkey
		$a_03_3 = {40 3d 00 02 00 00 72 90 01 01 81 90 02 05 4d 53 4d 50 75 90 01 01 68 00 02 00 00 8d 90 02 05 52 53 e8 90 00 } //01 00 
		$a_03_4 = {81 38 4d 53 4d 50 75 90 01 01 be 00 02 00 00 56 50 8d 85 90 01 04 50 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}