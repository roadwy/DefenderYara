
rule Trojan_Win32_Redline_DF_MTB{
	meta:
		description = "Trojan:Win32/Redline.DF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {88 45 db 0f b6 4d db 2b 4d dc 88 4d db 0f b6 55 db c1 fa 02 0f b6 45 db c1 e0 06 0b d0 88 55 db 0f b6 4d db 81 e9 8e 00 00 00 88 4d db 0f b6 55 db f7 da 88 55 db 0f b6 45 db f7 d0 88 45 db 8b 4d dc 8a 55 db 88 54 0d e8 e9 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Redline_DF_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.DF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {89 44 24 10 8b 44 24 4c 01 44 24 10 8b 4c 24 28 33 ca 89 4c 24 38 89 5c 24 30 8b 44 24 38 89 44 24 30 8b 44 24 10 31 44 24 30 8b 54 24 30 89 54 24 38 } //01 00 
		$a_01_1 = {8b 44 24 18 c1 e8 05 89 44 24 10 8b 44 24 10 33 74 24 28 03 44 24 48 } //00 00 
	condition:
		any of ($a_*)
 
}