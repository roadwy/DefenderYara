
rule Trojan_BAT_NjRat_NECK_MTB{
	meta:
		description = "Trojan:BAT/NjRat.NECK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 05 00 00 05 00 "
		
	strings :
		$a_01_0 = {39 39 35 39 66 64 35 37 2d 39 38 62 37 2d 34 30 38 33 2d 39 30 64 31 2d 33 36 64 36 34 31 64 65 32 33 32 31 } //02 00  9959fd57-98b7-4083-90d1-36d641de2321
		$a_01_1 = {6d 69 63 72 6f 6f 66 74 2e 65 78 65 } //02 00  microoft.exe
		$a_01_2 = {6d 69 63 72 6f 6f 66 74 2e 4d 79 } //01 00  microoft.My
		$a_01_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_01_4 = {67 65 74 5f 45 6e 74 72 79 50 6f 69 6e 74 } //00 00  get_EntryPoint
	condition:
		any of ($a_*)
 
}