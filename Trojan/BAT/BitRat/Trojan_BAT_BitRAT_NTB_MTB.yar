
rule Trojan_BAT_BitRAT_NTB_MTB{
	meta:
		description = "Trojan:BAT/BitRAT.NTB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 05 00 "
		
	strings :
		$a_03_0 = {07 17 58 17 2c fb 0b 07 06 8e 69 1e 2c f4 32 ca 16 3a 90 01 03 ff 90 00 } //01 00 
		$a_01_1 = {57 69 6e 64 6f 77 73 46 6f 72 6d 73 41 70 70 34 30 } //01 00  WindowsFormsApp40
		$a_01_2 = {53 00 71 00 67 00 73 00 77 00 79 00 6d 00 70 00 78 00 70 00 61 00 65 00 6b 00 75 00 6d 00 61 00 63 00 73 00 76 00 71 00 79 00 71 00 69 00 } //00 00  Sqgswympxpaekumacsvqyqi
	condition:
		any of ($a_*)
 
}