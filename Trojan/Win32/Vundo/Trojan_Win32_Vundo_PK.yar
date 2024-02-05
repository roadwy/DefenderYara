
rule Trojan_Win32_Vundo_PK{
	meta:
		description = "Trojan:Win32/Vundo.PK,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b6 00 2d 90 01 01 00 00 00 85 c0 74 90 00 } //0a 00 
		$a_01_1 = {8a 23 93 32 df 93 88 03 } //01 00 
		$a_03_2 = {0f b6 00 83 e8 90 01 01 85 c0 74 90 09 0b 00 a1 90 01 04 2b 05 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}