
rule Trojan_Win32_Matsnu_gen_B{
	meta:
		description = "Trojan:Win32/Matsnu.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 63 6f 6d 2f 74 65 6d 70 2f 61 2e 70 68 70 } //01 00  .com/temp/a.php
		$a_01_1 = {5b 8b 7d 08 81 3f 4c 5a 57 21 75 06 8b 47 04 } //01 00 
		$a_01_2 = {30 d0 31 c9 b1 08 d3 ea f8 d1 d8 73 05 35 20 83 b8 ed } //00 00 
	condition:
		any of ($a_*)
 
}