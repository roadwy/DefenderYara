
rule Trojan_Win32_Bumblebee_A{
	meta:
		description = "Trojan:Win32/Bumblebee.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {84 c0 74 09 33 c9 ff 90 01 04 00 cc 33 c9 e8 90 01 03 00 90 01 01 8b c8 e8 90 00 } //01 00 
		$a_03_1 = {84 c0 0f 85 90 01 02 00 00 33 c9 e8 90 01 04 48 8b c8 e8 90 01 04 48 8d 85 90 00 } //01 00 
		$a_03_2 = {48 8b c8 e8 90 01 04 83 ca ff 48 8b 0d 90 01 04 ff 15 90 09 07 00 33 c9 e8 90 00 } //01 00 
		$a_03_3 = {4f 00 00 00 48 8d 90 01 05 e8 90 01 07 48 8d 90 01 05 ba 4f 00 00 00 e8 90 01 07 48 8d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}