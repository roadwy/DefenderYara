
rule Trojan_Win32_Vundo_KE{
	meta:
		description = "Trojan:Win32/Vundo.KE,SIGNATURE_TYPE_PEHSTR_EXT,1f 00 1f 00 08 00 00 0a 00 "
		
	strings :
		$a_03_0 = {58 55 8b ec 53 90 09 09 00 68 90 01 04 90 90 90 90 90 90 90 00 } //0a 00 
		$a_01_1 = {c7 04 24 00 80 00 00 } //0a 00 
		$a_03_2 = {64 8b 3d 30 00 00 00 eb 90 01 01 eb eb eb eb eb eb eb eb eb eb 90 00 } //01 00 
		$a_03_3 = {c6 45 f7 72 90 02 04 c6 45 f8 33 90 02 04 c6 45 f9 32 90 00 } //01 00 
		$a_03_4 = {c6 45 f8 33 90 02 04 c6 45 f9 32 90 02 04 c6 45 fa 2e 90 00 } //01 00 
		$a_03_5 = {c6 45 f9 32 90 02 04 c6 45 fa 2e 90 02 04 c6 45 fb 64 90 00 } //01 00 
		$a_03_6 = {c6 45 fa 2e 90 02 04 c6 45 fb 64 90 02 04 c6 45 fc 6c 90 00 } //01 00 
		$a_03_7 = {c6 45 fb 64 90 02 04 c6 45 fc 6c 90 02 04 c6 45 fd 6c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}