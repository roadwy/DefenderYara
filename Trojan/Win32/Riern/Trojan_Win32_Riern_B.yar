
rule Trojan_Win32_Riern_B{
	meta:
		description = "Trojan:Win32/Riern.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {50 56 ff d7 89 45 e4 8d 85 90 01 02 ff ff 68 90 01 02 40 00 50 e8 90 01 04 59 90 00 } //01 00 
		$a_03_1 = {50 ff 55 fc 8d 85 90 01 02 ff ff 50 8d 85 90 01 02 ff ff 50 ff 55 f8 6a 08 8d 85 90 01 02 ff ff 6a 00 50 ff 55 e8 8d 85 90 01 02 ff ff 50 56 ff 55 f4 85 c0 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}