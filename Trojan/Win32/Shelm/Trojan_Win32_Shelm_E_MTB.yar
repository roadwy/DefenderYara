
rule Trojan_Win32_Shelm_E_MTB{
	meta:
		description = "Trojan:Win32/Shelm.E!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {80 34 18 59 40 8b 8d 90 01 02 ff ff 3b c1 90 00 } //02 00 
		$a_03_1 = {99 8d 7f 01 b9 90 01 04 f7 f9 8a 47 90 01 01 8b 8d 90 01 04 fe c2 32 c2 34 90 01 01 88 04 0e 46 81 fe 90 00 } //02 00 
		$a_03_2 = {99 8d 76 01 b9 90 01 04 f7 f9 8a 44 33 90 01 01 32 44 24 90 01 01 fe c2 32 c2 88 46 ff 83 ef 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}