
rule Trojan_Win32_Pigax_gen_A{
	meta:
		description = "Trojan:Win32/Pigax.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {6f 71 73 2e 76 64 63 } //01 00 
		$a_03_1 = {eb 0f 8b 44 24 08 0f b6 04 08 83 f0 90 01 01 88 04 0b 41 39 d1 72 ed 90 00 } //01 00 
		$a_01_2 = {eb 15 0f b7 45 fe 01 f8 0f be 10 0f be 4f 02 31 ca 88 10 } //01 00 
		$a_03_3 = {6a 00 6a 0a ff 75 fc e8 90 01 04 09 c0 75 6f 90 00 } //01 00 
		$a_01_4 = {66 89 45 10 66 81 7d 10 94 01 75 0e } //00 00 
	condition:
		any of ($a_*)
 
}