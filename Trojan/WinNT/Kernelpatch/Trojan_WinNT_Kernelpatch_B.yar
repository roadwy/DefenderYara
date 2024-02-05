
rule Trojan_WinNT_Kernelpatch_B{
	meta:
		description = "Trojan:WinNT/Kernelpatch.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {e9 34 01 00 00 8b 08 fa 0f 20 c0 25 ff ff fe ff 0f 22 c0 8b 06 89 04 91 0f 20 c0 0d 00 00 01 00 0f 22 c0 fb 83 a5 6c ff ff ff 00 e9 09 01 00 00 } //01 00 
		$a_03_1 = {5a 00 66 c7 45 90 01 01 77 00 66 c7 45 90 01 01 43 00 90 00 } //01 00 
		$a_03_2 = {4e 00 66 c7 85 90 01 01 ff ff ff 54 00 66 c7 85 90 01 01 ff ff ff 5c 00 66 c7 85 90 01 01 ff ff ff 43 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}