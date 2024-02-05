
rule Trojan_Win32_Azorult_NV_MTB{
	meta:
		description = "Trojan:Win32/Azorult.NV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8a 4c 01 15 8b 15 90 02 04 88 90 02 02 8b 90 02 05 81 90 02 05 75 0a c7 05 90 02 08 40 3b c1 72 90 01 01 e8 90 02 04 e8 90 02 04 33 90 01 01 3d 90 02 04 90 18 40 3d 90 02 04 7c 90 01 01 c7 05 90 02 08 ff 15 90 00 } //01 00 
		$a_02_1 = {8a 4c 01 15 8b 90 02 05 88 90 02 02 8b 90 02 05 81 90 02 05 90 18 40 3b 90 01 01 72 90 01 01 e8 90 01 04 e8 90 01 04 81 90 02 09 c7 05 90 02 08 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}