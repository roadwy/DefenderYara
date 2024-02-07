
rule VirTool_Win32_CeeInject_ME_bit{
	meta:
		description = "VirTool:Win32/CeeInject.ME!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {31 c0 0b 07 83 ef 90 01 01 f7 d0 f8 83 d8 90 01 01 c1 c8 90 01 01 d1 c0 01 f0 8d 40 90 01 01 8d 30 c1 c6 90 01 01 d1 ce 50 8f 02 f8 83 da 90 01 01 83 c1 90 01 01 eb 90 00 } //01 00 
		$a_03_1 = {f7 de 51 8d 05 90 01 04 05 90 01 04 50 8d 0d 90 01 04 81 c1 90 01 04 51 8d 0d 90 01 04 81 c1 90 01 04 51 8d 05 90 01 04 50 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_CeeInject_ME_bit_2{
	meta:
		description = "VirTool:Win32/CeeInject.ME!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f be 11 33 95 90 01 01 fe ff ff 8b 85 90 01 01 fe ff ff 03 85 90 01 01 fe ff ff 88 10 90 00 } //01 00 
		$a_03_1 = {0f b7 48 06 39 4d 90 01 01 0f 8d 90 01 02 00 00 8b 55 90 01 01 8b 45 90 01 01 03 42 3c 8b 4d 90 01 01 6b c9 90 01 01 8d 94 08 90 01 01 00 00 00 90 00 } //01 00 
		$a_03_2 = {6a 00 8b 55 90 01 01 8b 42 90 01 01 50 8b 4d 90 01 01 8b 55 90 01 01 03 51 90 01 01 52 8b 45 90 01 01 8b 4d 90 01 01 03 48 90 01 01 51 8b 55 90 01 01 52 a1 90 01 03 00 ff d0 90 00 } //00 00 
		$a_00_3 = {7e 15 } //00 00  ᕾ
	condition:
		any of ($a_*)
 
}