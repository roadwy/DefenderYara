
rule Trojan_Win32_Azorult_ND_MTB{
	meta:
		description = "Trojan:Win32/Azorult.ND!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {30 04 37 83 90 02 02 90 18 46 3b f3 90 18 90 18 a1 90 02 04 69 90 02 05 81 3d 90 02 08 a3 90 02 04 90 18 81 90 02 09 56 0f 90 02 06 81 90 02 05 81 90 02 09 90 18 8b 90 01 01 5e c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}