
rule Trojan_Win32_Scarsi_ARA_MTB{
	meta:
		description = "Trojan:Win32/Scarsi.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {83 f9 ff 74 29 8b 35 40 90 40 00 b8 67 66 66 66 f7 e9 c1 fa 02 8b c2 c1 e8 1f 03 c2 8d 14 80 03 d2 8b c1 2b c2 8a 90 c4 73 40 00 30 14 0e 41 3b 0d 4c 90 40 00 72 c9 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Scarsi_ARA_MTB_2{
	meta:
		description = "Trojan:Win32/Scarsi.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {8b 4d f0 83 c1 01 89 4d f0 8b 55 f0 3b 15 84 50 40 00 73 33 83 7d f0 00 7c 2b 8b 45 f0 99 b9 0a 00 00 00 f7 f9 8b 45 fc 0f be 0c 10 8b 15 6c 50 40 00 03 55 f0 0f be 02 33 c1 8b 0d 6c 50 40 00 03 4d f0 88 01 eb b9 } //00 00 
	condition:
		any of ($a_*)
 
}