
rule Trojan_Win32_KillDisk_K{
	meta:
		description = "Trojan:Win32/KillDisk.K,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 18 00 09 00 56 ff d3 8d 44 24 10 6a 00 50 8d 4c 24 20 6a 18 51 6a 00 6a 00 68 00 00 07 00 56 ff d3 } //01 00 
		$a_03_1 = {8a 0c 38 80 f1 90 01 01 88 0c 38 40 3d fe 01 00 00 7c ef 90 00 } //01 00 
		$a_03_2 = {68 00 02 00 00 57 56 ff 15 90 01 04 85 c0 74 5a 81 7c 24 14 00 02 00 00 72 50 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}