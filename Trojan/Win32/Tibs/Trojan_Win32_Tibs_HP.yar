
rule Trojan_Win32_Tibs_HP{
	meta:
		description = "Trojan:Win32/Tibs.HP,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {59 5a 85 d2 75 90 14 4a 41 52 51 90 02 01 90 03 03 0c 29 d2 52 90 02 05 6a 90 01 01 6a 90 01 01 6a 90 00 } //01 00 
		$a_01_1 = {03 4d 0c 03 4d 08 81 e9 } //02 00 
		$a_03_2 = {03 4d 0c 03 4d 08 81 e9 01 90 01 03 c9 90 09 06 00 90 03 02 02 59 5a 5a 59 85 d2 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}