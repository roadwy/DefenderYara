
rule Trojan_Win32_Startpage_KV{
	meta:
		description = "Trojan:Win32/Startpage.KV,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {69 65 78 70 6c 6f 72 65 2e 65 78 65 20 68 74 74 70 3a 2f 2f 77 77 77 2e 6d 79 31 33 33 2e 6e 65 74 2f 3f 32 00 fd 99 80 00 53 65 46 61 73 74 49 6e 73 74 61 6c 6c 32 5f 33 32 31 38 2e 65 78 65 } //01 00 
		$a_01_1 = {68 74 74 70 3a 2f 2f 77 77 77 2e 6a 64 39 2e 6e 65 74 2f 63 6f 75 6e 74 6e 65 77 2f 57 72 69 74 65 44 61 74 61 2e 61 73 70 78 3f 69 64 3d fd 8a 80 26 4d 41 43 3d fd 8b 80 26 6d 64 35 3d } //00 00 
	condition:
		any of ($a_*)
 
}