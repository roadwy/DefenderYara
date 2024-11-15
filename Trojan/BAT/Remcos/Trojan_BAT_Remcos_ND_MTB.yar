
rule Trojan_BAT_Remcos_ND_MTB{
	meta:
		description = "Trojan:BAT/Remcos.ND!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_03_0 = {26 16 02 03 02 4b 03 04 61 05 61 58 0e 07 0e 04 e0 95 58 7e 24 00 00 04 0e 06 17 59 e0 95 58 0e 05 28 ?? 00 00 06 58 54 2a } //1
		$a_81_1 = {64 37 62 33 36 36 36 63 2d 38 34 39 37 2d 34 32 36 39 2d 38 64 33 66 2d 32 32 63 63 61 38 37 34 62 62 61 38 } //3 d7b3666c-8497-4269-8d3f-22cca874bba8
		$a_81_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_81_3 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 41 73 79 6e 63 } //1 DownloadDataAsync
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*3+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=6
 
}