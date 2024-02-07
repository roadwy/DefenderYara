
rule Trojan_BAT_Vidar_MBCO_MTB{
	meta:
		description = "Trojan:BAT/Vidar.MBCO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 21 47 00 65 00 74 00 45 00 78 00 70 00 6f 00 72 00 74 00 65 00 64 00 54 00 79 00 70 00 65 00 73 00 00 21 46 00 72 00 6f 00 6d 00 42 00 61 00 73 00 65 00 36 00 34 00 53 00 74 00 72 00 69 00 6e 00 67 00 00 4b } //01 00  ℀GetExportedTypes℀FromBase64String䬀
		$a_01_1 = {31 00 38 00 35 00 2e 00 32 00 35 00 34 00 2e 00 33 00 37 00 2e 00 31 00 30 00 38 00 } //00 00  185.254.37.108
	condition:
		any of ($a_*)
 
}