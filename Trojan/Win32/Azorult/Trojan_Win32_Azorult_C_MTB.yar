
rule Trojan_Win32_Azorult_C_MTB{
	meta:
		description = "Trojan:Win32/Azorult.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {33 d2 f7 75 90 01 01 8b 45 90 01 01 0f b6 0c 10 8b 55 90 01 01 03 55 90 01 01 0f b6 02 33 c1 8b 4d 90 01 01 03 4d 90 01 01 88 01 90 00 } //02 00 
		$a_03_1 = {0f b7 45 ec 6b c8 90 01 01 8b 55 e8 8b 44 0a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}