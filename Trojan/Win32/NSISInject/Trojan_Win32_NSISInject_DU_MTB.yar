
rule Trojan_Win32_NSISInject_DU_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.DU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 06 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 c9 85 db 74 90 01 01 8a 04 39 2c 49 34 48 2c 32 34 b6 88 04 39 41 3b cb 72 90 00 } //01 00 
		$a_03_1 = {33 c9 85 db 74 90 01 01 8a 04 39 04 6f 34 a7 2c 79 34 38 04 3a 88 04 39 41 3b cb 72 90 00 } //01 00 
		$a_03_2 = {33 c9 85 db 74 90 01 01 8a 04 39 2c 14 34 fd 04 6a 34 a4 fe c0 34 19 88 04 39 41 3b cb 72 90 00 } //01 00 
		$a_03_3 = {33 c9 85 db 74 90 01 01 8a 04 39 2c 57 34 78 04 0c 34 b7 fe c0 34 1d 2c 02 88 04 39 41 3b cb 72 90 00 } //01 00 
		$a_03_4 = {33 c9 85 db 74 90 01 01 8a 04 39 2c 62 34 1f 2c 08 34 9f fe c0 34 10 2c 3b 88 04 39 41 3b cb 72 90 00 } //01 00 
		$a_03_5 = {33 c9 85 db 74 90 01 01 8a 04 39 04 19 34 9b 2c 39 34 86 2c 05 88 04 39 41 3b cb 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}