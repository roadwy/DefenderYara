
rule Trojan_Win32_Stealer_BL_MTB{
	meta:
		description = "Trojan:Win32/Stealer.BL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //05 00 
		$a_01_1 = {2b c1 8b d8 33 d2 8b c6 f7 f3 8b 45 0c 8d 0c 3e 8a 04 02 8b 55 08 32 04 0a 46 88 01 } //00 00 
		$a_00_2 = {5d 04 00 00 34 } //27 05 
	condition:
		any of ($a_*)
 
}