
rule Trojan_Win32_DyCode_A{
	meta:
		description = "Trojan:Win32/DyCode.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 02 00 "
		
	strings :
		$a_03_0 = {bd 4b 48 43 42 66 b8 04 00 90 02 02 cc 90 00 } //01 00 
		$a_03_1 = {50 6a 40 8b 45 90 01 01 50 8b 45 fc 50 ff 15 90 01 04 8b 45 fc ff d0 90 00 } //01 00 
		$a_03_2 = {c6 03 c3 e8 90 01 04 5a 5b c3 90 00 } //01 00 
		$a_03_3 = {8b 16 88 c3 32 da c1 e8 08 33 04 9d 90 01 04 88 c3 32 de c1 e8 08 33 04 9d 90 01 04 c1 ea 10 90 00 } //01 00 
		$a_00_4 = {53 48 45 4c 4c 00 00 00 43 4f 44 45 00 } //00 00 
	condition:
		any of ($a_*)
 
}