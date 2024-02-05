
rule Trojan_Win32_AbaddonPOS_A{
	meta:
		description = "Trojan:Win32/AbaddonPOS.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {80 39 30 72 90 01 01 80 39 39 90 02 0f 80 39 5e 90 02 04 80 39 3d 90 00 } //01 00 
		$a_01_1 = {31 0b 81 3b 55 89 e5 8b 74 0e 83 f8 00 75 09 31 0b 29 c3 31 c0 41 } //01 00 
		$a_01_2 = {81 be a0 01 00 00 00 f4 01 00 74 24 81 be a0 01 00 00 00 e8 03 00 74 18 81 be a0 01 00 00 00 dc 05 00 74 0c 81 be a0 01 00 00 00 d6 06 00 75 08 6a 05 } //00 00 
		$a_00_3 = {5d } //04 00 
	condition:
		any of ($a_*)
 
}