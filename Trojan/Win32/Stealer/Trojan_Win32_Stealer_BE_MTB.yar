
rule Trojan_Win32_Stealer_BE_MTB{
	meta:
		description = "Trojan:Win32/Stealer.BE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {40 3d 8a 36 13 01 89 44 24 90 01 01 0f 8c 90 00 } //01 00 
		$a_03_1 = {46 81 fe 93 22 0b 18 89 2d 90 02 04 7c be 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}