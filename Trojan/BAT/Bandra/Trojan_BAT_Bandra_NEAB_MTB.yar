
rule Trojan_BAT_Bandra_NEAB_MTB{
	meta:
		description = "Trojan:BAT/Bandra.NEAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 04 00 00 05 00 "
		
	strings :
		$a_01_0 = {35 66 31 36 61 62 30 37 2d 65 64 36 35 2d 34 36 61 34 2d 38 38 34 32 2d 64 37 30 63 65 30 65 39 34 30 30 37 } //04 00  5f16ab07-ed65-46a4-8842-d70ce0e94007
		$a_01_1 = {45 00 3a 00 5c 00 41 00 61 00 72 00 6f 00 6e 00 73 00 20 00 53 00 74 00 75 00 66 00 66 00 5c 00 2e 00 4e 00 45 00 54 00 20 00 44 00 65 00 76 00 65 00 6c 00 6f 00 70 00 6d 00 65 00 6e 00 74 00 5c 00 5f 00 50 00 72 00 6f 00 6a 00 65 00 63 00 74 00 73 00 5c 00 46 00 6f 00 6c 00 64 00 65 00 72 00 49 00 54 00 } //04 00  E:\Aarons Stuff\.NET Development\_Projects\FolderIT
		$a_01_2 = {54 00 68 00 69 00 73 00 20 00 61 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 20 00 69 00 73 00 20 00 70 00 72 00 6f 00 74 00 65 00 63 00 74 00 65 00 64 00 20 00 62 00 79 00 } //01 00  This assembly is protected by
		$a_01_3 = {46 6f 6c 64 65 72 43 72 65 61 74 6f 72 } //00 00  FolderCreator
	condition:
		any of ($a_*)
 
}