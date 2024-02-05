
rule Trojan_Win32_Regin_D_dha{
	meta:
		description = "Trojan:Win32/Regin.D!dha,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {c7 45 e4 10 00 00 00 c7 45 ec 07 00 00 00 c7 45 fc b8 0b 00 00 ff 15 } //01 00 
		$a_03_1 = {6a 01 6a 05 58 e8 90 01 04 6a 00 6a 04 90 00 } //01 00 
		$a_03_2 = {6a 01 6a 06 58 e8 90 01 04 6a 00 6a 07 eb 90 00 } //01 00 
		$a_03_3 = {6a 01 6a 03 58 e8 90 01 04 59 6a 01 6a 00 90 00 } //01 00 
		$a_03_4 = {6a 01 6a 02 58 e8 90 01 04 56 6a 04 58 e8 90 01 04 59 59 e8 90 01 04 6a 01 90 00 } //00 00 
		$a_00_5 = {5d 04 00 } //00 41 
	condition:
		any of ($a_*)
 
}