
rule Trojan_Win32_Sefnit_CB{
	meta:
		description = "Trojan:Win32/Sefnit.CB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {83 78 14 08 72 02 8b 00 6a 02 50 ff 15 90 01 04 c6 45 fc 90 01 01 56 53 90 00 } //01 00 
		$a_01_1 = {5b 00 74 00 61 00 73 00 6b 00 5f 00 73 00 74 00 61 00 72 00 74 00 5d 00 00 00 } //01 00 
		$a_01_2 = {2c 00 73 00 63 00 68 00 65 00 64 00 75 00 6c 00 65 00 5f 00 74 00 61 00 73 00 6b 00 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}