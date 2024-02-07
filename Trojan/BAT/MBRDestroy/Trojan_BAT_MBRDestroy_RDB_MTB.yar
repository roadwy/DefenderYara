
rule Trojan_BAT_MBRDestroy_RDB_MTB{
	meta:
		description = "Trojan:BAT/MBRDestroy.RDB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {37 66 36 39 66 66 35 36 2d 65 65 34 33 2d 34 36 37 39 2d 62 66 32 34 2d 38 33 62 33 37 35 61 63 33 39 32 31 } //01 00  7f69ff56-ee43-4679-bf24-83b375ac3921
		$a_01_1 = {4f 75 74 53 6f 73 74 20 53 65 72 76 69 63 65 20 44 72 69 76 65 72 } //01 00  OutSost Service Driver
		$a_01_2 = {44 00 69 00 73 00 61 00 62 00 6c 00 65 00 43 00 4d 00 44 00 } //01 00  DisableCMD
		$a_01_3 = {44 00 69 00 73 00 61 00 62 00 6c 00 65 00 52 00 65 00 67 00 69 00 73 00 74 00 72 00 79 00 54 00 6f 00 6f 00 6c 00 73 00 } //00 00  DisableRegistryTools
	condition:
		any of ($a_*)
 
}