
rule Trojan_Win32_Azorult_NG_MTB{
	meta:
		description = "Trojan:Win32/Azorult.NG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {30 01 46 3b f7 90 18 81 90 02 05 90 18 8b 90 02 03 8d 90 02 02 90 18 a1 90 02 04 69 90 02 05 05 90 02 04 a3 90 02 04 0f 90 02 06 25 90 02 04 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}