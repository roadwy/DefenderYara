
rule Trojan_Win32_Androm_R_MTB{
	meta:
		description = "Trojan:Win32/Androm.R!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {8a 84 0a 56 c4 08 00 8b 15 90 02 04 88 04 0a 81 c4 74 02 00 00 90 00 } //01 00 
		$a_01_1 = {33 ce 33 c1 2b f8 } //01 00 
		$a_01_2 = {33 d7 33 c2 2b f0 } //00 00 
	condition:
		any of ($a_*)
 
}