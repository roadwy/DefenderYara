
rule Trojan_Win32_Tibs_IF{
	meta:
		description = "Trojan:Win32/Tibs.IF,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {03 4d 0c 03 4d 08 81 e9 } //01 00 
		$a_03_1 = {83 e8 fe 8b 28 b9 90 01 04 ff 94 29 90 01 04 90 02 03 09 d2 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}