
rule Trojan_Win32_Redline_DAL_MTB{
	meta:
		description = "Trojan:Win32/Redline.DAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 03 00 "
		
	strings :
		$a_03_0 = {0f b6 10 81 e2 90 02 04 8b 45 08 03 45 d4 0f b6 08 33 ca 8b 55 08 03 55 d4 88 0a e9 90 00 } //01 00 
		$a_01_1 = {6e 67 76 66 68 6b 7a 6f 76 69 68 6f 72 6b 75 6a 76 69 77 63 67 67 68 62 76 6d 6a 73 61 6c 6a 65 6a 75 79 79 72 6d } //01 00  ngvfhkzovihorkujviwcgghbvmjsaljejuyyrm
		$a_01_2 = {74 73 65 73 6b 7a 74 67 77 69 61 6d 6d 6a 62 72 61 67 75 64 65 6c 73 72 76 67 73 68 64 6d 68 76 6d 63 79 6b 66 69 63 62 66 77 71 68 66 63 64 6c 6b 69 6f 65 77 70 6a 61 6a 61 6b 75 6c 73 66 79 72 64 75 6a 7a } //00 00  tseskztgwiammjbragudelsrvgshdmhvmcykficbfwqhfcdlkioewpjajakulsfyrdujz
	condition:
		any of ($a_*)
 
}