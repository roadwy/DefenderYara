
rule Trojan_Win32_Farfli_BL_MTB{
	meta:
		description = "Trojan:Win32/Farfli.BL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8d 55 e8 b1 cc 03 d0 2a c8 40 32 0a 88 0c 13 83 f8 05 76 } //01 00 
		$a_01_1 = {53 65 72 76 69 63 65 4d 61 69 6e } //00 00 
	condition:
		any of ($a_*)
 
}