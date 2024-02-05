
rule Trojan_Win32_Tracur_AZ{
	meta:
		description = "Trojan:Win32/Tracur.AZ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {f6 40 2c 01 74 1b 8b 43 10 83 38 01 75 07 8b c3 e8 90 01 04 68 10 27 00 00 e8 90 01 04 eb e5 90 00 } //01 00 
		$a_03_1 = {68 f4 01 00 00 e8 90 01 04 6a 00 57 56 e8 90 01 04 68 f4 01 00 00 e8 90 01 04 43 83 fb 03 77 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}