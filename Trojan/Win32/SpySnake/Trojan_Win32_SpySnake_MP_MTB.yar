
rule Trojan_Win32_SpySnake_MP_MTB{
	meta:
		description = "Trojan:Win32/SpySnake.MP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 05 00 "
		
	strings :
		$a_01_0 = {8a 04 39 2c 5c 34 99 2c 23 34 ed 04 3a 34 aa fe c8 88 04 39 47 3b fb 72 } //05 00 
		$a_01_1 = {51 68 80 00 00 00 6a 03 51 6a 01 68 00 00 00 80 ff 75 10 ff 15 } //00 00 
	condition:
		any of ($a_*)
 
}