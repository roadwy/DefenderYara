
rule Trojan_Win32_Fareit_DB_MTB{
	meta:
		description = "Trojan:Win32/Fareit.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {0f b6 ca 8a 9c 0d fc fe ff ff 32 1c 39 48 30 58 01 fe ca 4e 75 ea } //01 00 
		$a_01_1 = {0f b6 ca 8a 9c 0d fc fe ff ff 02 1c 39 48 00 58 01 fe ca 4e 75 ea } //01 00 
		$a_01_2 = {47 65 74 54 69 63 6b 43 6f 75 6e 74 } //01 00 
		$a_01_3 = {51 75 65 72 79 50 65 72 66 6f 72 6d 61 6e 63 65 43 6f 75 6e 74 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}