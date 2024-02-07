
rule Trojan_Win32_Startpage_OF{
	meta:
		description = "Trojan:Win32/Startpage.OF,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 65 74 63 5c 73 65 72 76 69 63 65 } //01 00  WINDOWS\system32\drivers\etc\service
		$a_00_1 = {50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 73 74 61 72 74 75 70 } //01 00  Program Files\startup
		$a_03_2 = {c7 44 24 04 94 00 00 00 ff 15 90 01 04 83 7c 24 10 02 75 0c 83 7c 24 04 05 b8 90 01 04 73 05 b8 90 01 04 50 68 90 01 04 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}