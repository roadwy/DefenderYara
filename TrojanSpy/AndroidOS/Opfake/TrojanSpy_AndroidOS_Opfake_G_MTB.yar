
rule TrojanSpy_AndroidOS_Opfake_G_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Opfake.G!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {4c 66 6b 6a 73 67 6d 6a 6c 2f 63 65 69 6e 6e 79 6b 61 73 2f 62 61 73 67 78 6a 6b 66 66 3b } //01 00  Lfkjsgmjl/ceinnykas/basgxjkff;
		$a_00_1 = {4c 76 65 79 6b 69 6d 73 69 2f 70 75 61 71 63 6b 2f 6c 6b 74 63 77 61 3b } //01 00  Lveykimsi/puaqck/lktcwa;
		$a_00_2 = {2f 65 74 71 73 61 75 79 61 3b } //00 00  /etqsauya;
		$a_00_3 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}