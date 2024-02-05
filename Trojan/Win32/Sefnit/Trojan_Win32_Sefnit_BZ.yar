
rule Trojan_Win32_Sefnit_BZ{
	meta:
		description = "Trojan:Win32/Sefnit.BZ,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 03 00 "
		
	strings :
		$a_03_0 = {46 83 fe 03 72 bd c6 45 90 01 01 01 eb 88 6a 04 90 00 } //03 00 
		$a_03_1 = {6a 05 59 6a 0a 58 89 4d 90 01 01 89 4d 90 01 01 8d 8d 90 01 04 c7 45 90 01 01 3c 00 00 00 90 00 } //01 00 
		$a_01_2 = {6f 00 63 00 6c 00 2e 00 65 00 78 00 65 00 } //01 00 
		$a_01_3 = {63 00 64 00 61 00 2e 00 65 00 78 00 65 00 } //01 00 
		$a_01_4 = {63 00 70 00 75 00 2e 00 65 00 78 00 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}