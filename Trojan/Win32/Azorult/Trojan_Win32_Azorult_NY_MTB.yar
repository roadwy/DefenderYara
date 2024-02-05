
rule Trojan_Win32_Azorult_NY_MTB{
	meta:
		description = "Trojan:Win32/Azorult.NY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {88 14 30 81 3d 90 02 08 90 18 46 3b 35 90 02 04 90 18 8b 90 02 05 8a 90 02 03 a1 90 00 } //01 00 
		$a_02_1 = {88 14 30 81 3d 90 02 08 90 18 46 3b 90 02 09 e8 90 02 04 e8 90 02 05 8b 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}