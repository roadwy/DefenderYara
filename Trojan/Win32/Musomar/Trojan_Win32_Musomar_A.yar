
rule Trojan_Win32_Musomar_A{
	meta:
		description = "Trojan:Win32/Musomar.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 02 00 "
		
	strings :
		$a_03_0 = {68 2b 80 00 00 6a 00 ff 15 90 01 03 00 85 c0 7c 90 01 01 8d 90 01 01 ec fc ff ff 90 01 01 68 90 01 03 00 68 04 01 00 00 8d 90 00 } //02 00 
		$a_03_1 = {aa 68 95 00 00 00 8d 90 01 01 68 ff ff ff 90 00 } //01 00 
		$a_01_2 = {83 bd 78 ff ff ff 05 73 2a 8b 8d 78 ff ff ff 8b 94 8d 64 ff ff ff } //01 00 
		$a_01_3 = {70 68 6f 62 6f 73 2e 6e 61 6d 65 } //01 00 
		$a_01_4 = {64 72 76 72 73 63 } //00 00 
	condition:
		any of ($a_*)
 
}