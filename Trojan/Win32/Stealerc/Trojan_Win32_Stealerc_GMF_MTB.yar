
rule Trojan_Win32_Stealerc_GMF_MTB{
	meta:
		description = "Trojan:Win32/Stealerc.GMF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 0a 00 "
		
	strings :
		$a_01_0 = {0f b6 c6 2b df c1 c2 f9 c1 ca 0d 66 c1 db 77 41 66 f7 eb 66 f7 e8 bb f8 00 00 00 66 c1 ce b9 03 cb 66 f7 e7 41 c1 e3 5a 23 c3 66 40 66 33 fb 66 c1 d1 fd } //01 00 
		$a_01_1 = {30 00 00 00 8b 7f 0c 8b 77 0c 8b 06 } //01 00 
		$a_03_2 = {5c 4d 69 63 72 6f 73 6f 66 74 2e 4e 45 54 5c 46 72 61 6d 65 77 6f 72 6b 5c 90 02 20 5c 41 70 70 4c 61 75 6e 63 68 2e 65 78 65 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}