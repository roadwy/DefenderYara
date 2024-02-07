
rule Trojan_BAT_Dcstl_NDY_MTB{
	meta:
		description = "Trojan:BAT/Dcstl.NDY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 05 00 "
		
	strings :
		$a_03_0 = {28 13 00 00 0a 28 90 01 03 0a 07 6f 90 01 03 0a 6f 90 01 03 0a 6f 90 01 03 0a 0c 08 72 90 01 03 70 28 90 01 03 06 2c 28 02 08 72 90 01 03 70 28 90 01 03 06 72 90 01 03 70 08 72 90 01 03 70 28 90 01 03 06 28 90 01 03 0a 17 73 90 01 03 06 2a 02 72 90 01 03 70 16 73 90 01 03 06 2a 90 00 } //01 00 
		$a_01_1 = {63 6f 70 79 32 73 74 61 72 74 75 70 } //01 00  copy2startup
		$a_01_2 = {44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 } //00 00  DownloadString
	condition:
		any of ($a_*)
 
}