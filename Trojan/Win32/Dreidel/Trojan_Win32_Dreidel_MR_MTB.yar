
rule Trojan_Win32_Dreidel_MR_MTB{
	meta:
		description = "Trojan:Win32/Dreidel.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {c1 e8 05 89 90 02 05 8b 90 02 06 01 90 02 05 8b 90 02 03 c1 90 02 03 03 90 02 06 8d 90 02 03 33 90 02 05 81 3d 90 02 08 c7 05 90 02 08 90 18 8b 90 02 05 33 90 02 05 89 90 00 } //01 00 
		$a_02_1 = {c1 e8 05 03 90 02 05 c7 05 90 02 08 89 90 02 05 33 90 02 05 33 90 02 05 2b 90 02 03 8b 90 02 03 29 90 02 03 ff 90 02 03 0f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}