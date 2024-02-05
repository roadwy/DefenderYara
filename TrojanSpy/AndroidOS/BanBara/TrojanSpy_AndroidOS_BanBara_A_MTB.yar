
rule TrojanSpy_AndroidOS_BanBara_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/BanBara.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {62 61 6e 6b 43 72 65 64 73 24 64 65 6c 65 67 61 74 65 } //01 00 
		$a_00_1 = {50 61 79 6d 65 6e 74 48 69 6a 61 72 6b } //01 00 
		$a_00_2 = {6d 6f 62 69 6c 65 2f 55 70 6c 6f 61 64 2f 43 6f 6c 6c 65 63 74 65 64 } //01 00 
		$a_00_3 = {62 72 61 7a 69 6c 42 61 6e 6b 53 77 69 74 63 68 24 64 65 6c 65 67 61 74 65 } //01 00 
		$a_00_4 = {67 65 74 41 69 6d 65 64 53 6d 73 } //01 00 
		$a_00_5 = {67 65 74 42 61 6e 6b 53 65 74 74 69 6e 67 } //00 00 
	condition:
		any of ($a_*)
 
}