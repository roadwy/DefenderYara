
rule Trojan_Win32_Windam_A{
	meta:
		description = "Trojan:Win32/Windam.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {38 36 61 66 63 34 33 38 36 38 66 6c 6b 67 64 62 64 34 30 66 62 66 36 64 35 65 64 35 30 39 30 35 00 } //01 00 
		$a_03_1 = {68 2f 75 00 00 8d 8d 90 01 02 ff ff 6a 00 c7 45 fc 01 00 00 00 51 c6 85 90 01 02 ff ff 00 e8 90 01 04 83 c4 0c 6a 00 6a 00 6a 00 6a 00 68 90 01 04 ff 15 90 01 04 8b f8 85 ff 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}