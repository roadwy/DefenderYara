
rule Trojan_Win32_Azorult_RK_MTB{
	meta:
		description = "Trojan:Win32/Azorult.RK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {69 c0 70 00 00 00 03 45 90 01 01 0f b7 40 90 01 01 89 45 90 01 01 8b 45 90 01 01 89 45 90 01 01 8b 4d 90 01 01 33 4d 90 01 01 89 4d 90 01 01 8b 4d 90 01 01 03 4d 90 01 01 89 4d 90 01 01 e9 90 01 04 8d 05 90 01 04 b9 0e 00 00 00 8d 55 90 01 01 83 ec 0c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}