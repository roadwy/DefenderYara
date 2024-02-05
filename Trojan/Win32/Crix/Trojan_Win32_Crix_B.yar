
rule Trojan_Win32_Crix_B{
	meta:
		description = "Trojan:Win32/Crix.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {6a 1c 5f f7 ff 8a 82 90 01 04 30 01 46 3b 75 0c 7e e4 90 00 } //01 00 
		$a_01_1 = {7f f7 b9 a9 f1 a7 1f } //01 00 
		$a_03_2 = {ff ff 6a 14 68 90 01 04 e8 90 01 02 ff ff 6a 12 68 90 01 04 e8 90 01 02 ff ff 6a 12 68 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}