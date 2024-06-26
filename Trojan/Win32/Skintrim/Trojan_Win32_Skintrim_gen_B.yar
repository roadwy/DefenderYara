
rule Trojan_Win32_Skintrim_gen_B{
	meta:
		description = "Trojan:Win32/Skintrim.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 06 00 00 fffffff8 ffffffff "
		
	strings :
		$a_00_0 = {72 73 72 63 00 } //0a 00 
		$a_00_1 = {e0 00 0f 01 0b 01 06 00 } //0a 00 
		$a_00_2 = {4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00 b8 } //01 00 
		$a_02_3 = {8b c7 2b cf be 90 01 03 00 8a 14 01 88 10 40 4e 75 f7 89 90 00 } //01 00 
		$a_02_4 = {4f 75 f7 89 90 09 0f 00 8b 90 01 01 2b 90 01 01 bf 90 01 04 8a 14 90 01 01 88 90 00 } //01 00 
		$a_02_5 = {4a 75 f7 89 90 09 0f 00 8b 90 01 01 2b 90 01 01 90 04 01 03 ba be bf 90 01 04 8a 90 01 02 88 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}