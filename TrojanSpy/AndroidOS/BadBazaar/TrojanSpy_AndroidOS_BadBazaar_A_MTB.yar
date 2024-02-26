
rule TrojanSpy_AndroidOS_BadBazaar_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/BadBazaar.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 68 6f 6e 65 46 6f 72 6d 61 74 73 2e 64 61 74 } //01 00  PhoneFormats.dat
		$a_01_1 = {74 70 73 3a 2f 2f 66 6c 79 67 72 61 6d 2e 6f 72 67 3a 34 34 33 32 2f 61 70 69 2f } //01 00  tps://flygram.org:4432/api/
		$a_01_2 = {41 6c 6c 6f 77 52 65 61 64 43 61 6c 6c 41 6e 64 4c 6f 67 } //01 00  AllowReadCallAndLog
		$a_01_3 = {6f 72 67 2e 74 65 6c 65 67 72 61 6d 2e 46 6c 79 47 72 61 6d } //00 00  org.telegram.FlyGram
	condition:
		any of ($a_*)
 
}