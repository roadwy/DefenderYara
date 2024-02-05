
rule Trojan_Win32_Startpage_NO{
	meta:
		description = "Trojan:Win32/Startpage.NO,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 61 74 20 45 78 70 6c 6f 72 65 72 5c 74 61 72 67 65 74 2e 6c 6e 6b 00 68 74 74 70 3a 2f 2f 77 77 77 2e 74 74 32 36 35 2e 6e 65 74 2f 00 fe 81 11 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 49 45 58 50 4c 4f 52 45 2e 45 58 45 00 6f 70 65 6e 00 61 74 74 72 69 62 00 } //01 00 
		$a_01_1 = {64 65 6c 20 22 fd 97 80 5c fd 9c 80 22 00 69 66 20 65 78 69 73 74 20 20 20 22 fd 97 80 5c fd 9c 80 22 20 20 20 67 6f 74 6f 20 20 20 70 70 00 64 65 6c 20 25 30 00 } //00 00 
	condition:
		any of ($a_*)
 
}