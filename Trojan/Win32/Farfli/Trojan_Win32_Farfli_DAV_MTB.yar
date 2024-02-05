
rule Trojan_Win32_Farfli_DAV_MTB{
	meta:
		description = "Trojan:Win32/Farfli.DAV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 14 01 80 c2 66 80 f2 fe 88 14 01 41 3b ce 7c } //01 00 
		$a_03_1 = {8b 41 08 6a ff 50 ff 15 90 01 04 68 2c 01 00 00 ff 15 90 00 } //01 00 
		$a_01_2 = {50 8d 4c 24 10 50 51 50 50 8b 86 a8 00 00 00 8d 54 24 24 6a 0c 52 68 04 00 00 98 50 c7 44 24 34 01 00 00 00 c7 44 24 38 20 bf 02 00 c7 44 24 3c 88 13 00 00 ff 15 } //01 00 
		$a_01_3 = {50 6c 75 67 69 6e 4d 65 } //00 00 
	condition:
		any of ($a_*)
 
}