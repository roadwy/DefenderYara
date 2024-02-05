
rule Trojan_Win32_Stealer_CM_MTB{
	meta:
		description = "Trojan:Win32/Stealer.CM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {30 49 5d d3 b2 90 01 04 d2 cc 37 93 90 00 } //01 00 
		$a_01_1 = {81 ef 04 00 00 00 33 3c 24 31 3c 24 33 3c 24 } //00 00 
	condition:
		any of ($a_*)
 
}