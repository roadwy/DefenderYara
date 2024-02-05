
rule Adware_MacOS_Adload_C_MTB{
	meta:
		description = "Adware:MacOS/Adload.C!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {4b 65 79 38 69 73 55 6e 69 71 75 65 79 71 5f 6e 5f 78 53 62 74 46 53 53 5f 79 70 54 67 35 54 66 34 6e 78 6e 6e 5f 6e 00 5f 24 73 53 44 79 71 5f 53 67 78 63 69 73 53 53 5f 79 70 54 67 35 54 66 34 6e 67 58 6e 5f 6e 00 5f } //01 00 
		$a_01_1 = {73 68 61 72 65 64 55 73 65 72 44 65 66 61 75 6c 74 73 } //00 00 
	condition:
		any of ($a_*)
 
}