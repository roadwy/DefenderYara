
rule Trojan_Win32_Azorult_NE_MTB{
	meta:
		description = "Trojan:Win32/Azorult.NE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {33 c0 81 ff 90 02 04 0f 90 02 02 46 3b f7 90 18 8a 90 02 06 88 90 00 } //01 00 
		$a_02_1 = {30 04 1f 47 3b 90 01 01 90 18 81 fe 90 02 04 90 18 e8 90 00 } //02 00 
		$a_02_2 = {30 04 1f 47 3b 90 01 01 90 18 81 fe 90 02 04 90 18 90 18 69 90 02 09 81 3d 90 02 08 a3 90 02 04 90 18 05 90 02 04 a3 90 02 04 c1 90 02 02 25 90 02 04 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}