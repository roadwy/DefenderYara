
rule Trojan_Win64_Niugpy_B{
	meta:
		description = "Trojan:Win64/Niugpy.B,SIGNATURE_TYPE_ARHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {81 fa 7e d2 b1 61 74 04 } //01 00 
		$a_01_1 = {81 fa 78 ea ff ff 8b da 48 8b f9 75 0c } //01 00 
		$a_01_2 = {81 e1 f0 00 ff ff 44 8d 81 88 ff 00 00 49 8b ca 41 c1 e0 10 } //00 00 
	condition:
		any of ($a_*)
 
}