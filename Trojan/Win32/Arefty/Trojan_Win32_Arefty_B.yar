
rule Trojan_Win32_Arefty_B{
	meta:
		description = "Trojan:Win32/Arefty.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {2b ca d1 f9 68 90 01 04 8d 41 fb 50 8d 47 0a 50 e8 90 01 02 00 00 83 c4 0c 8d 44 24 90 01 01 6a 5c 90 00 } //01 00 
		$a_03_1 = {2b ca d1 f9 68 90 01 04 8d 41 fb 50 8d 46 0a 50 e8 90 01 02 00 00 8b 44 24 90 01 01 83 c4 0c 33 c9 56 66 89 48 02 8d 44 24 90 01 01 68 0d 01 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}