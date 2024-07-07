
rule TrojanDownloader_BAT_Amadey_RDA_MTB{
	meta:
		description = "TrojanDownloader:BAT/Amadey.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {33 34 65 66 66 61 35 35 2d 63 30 35 65 2d 34 32 38 30 2d 38 31 62 34 2d 36 62 37 61 32 31 64 30 36 64 31 36 } //1 34effa55-c05e-4280-81b4-6b7a21d06d16
		$a_01_1 = {53 65 69 6c } //1 Seil
		$a_01_2 = {2f 00 2f 00 76 00 61 00 6c 00 6f 00 72 00 61 00 6e 00 74 00 63 00 68 00 65 00 61 00 74 00 73 00 62 00 6f 00 73 00 73 00 2e 00 63 00 6f 00 6d 00 2f 00 75 00 70 00 6c 00 6f 00 61 00 64 00 2f 00 } //1 //valorantcheatsboss.com/upload/
		$a_03_3 = {11 04 91 20 28 03 00 00 59 d2 9c 00 11 04 17 58 13 04 11 04 7e 90 01 04 8e 69 fe 04 13 05 11 05 90 00 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*2) >=5
 
}