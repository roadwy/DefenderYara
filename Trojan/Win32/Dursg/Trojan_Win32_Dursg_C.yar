
rule Trojan_Win32_Dursg_C{
	meta:
		description = "Trojan:Win32/Dursg.C,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {72 00 65 00 71 00 75 00 65 00 73 00 74 00 2e 00 70 00 68 00 70 00 3f 00 61 00 69 00 64 00 3d 00 25 00 73 00 } //01 00  request.php?aid=%s
		$a_03_1 = {51 50 6a 00 ff d2 90 09 14 00 8b 44 24 04 8b 90 90 90 01 04 6a 00 6a 00 8d 88 90 00 } //01 00 
		$a_01_2 = {3c 01 74 42 6a 00 68 80 00 00 00 6a 03 6a 00 6a 03 } //00 00 
	condition:
		any of ($a_*)
 
}