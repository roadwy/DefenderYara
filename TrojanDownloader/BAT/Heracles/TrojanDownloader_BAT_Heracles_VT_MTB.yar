
rule TrojanDownloader_BAT_Heracles_VT_MTB{
	meta:
		description = "TrojanDownloader:BAT/Heracles.VT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_81_0 = {4b 75 74 75 70 68 61 6e 65 4f 74 6f 6d 61 73 79 6f 6e 75 2e 50 72 6f 70 65 72 74 69 65 73 } //2 KutuphaneOtomasyonu.Properties
		$a_81_1 = {24 30 39 63 32 36 61 39 66 2d 32 64 30 35 2d 34 61 36 35 2d 38 61 63 31 2d 61 30 31 65 62 64 64 37 64 30 31 32 } //2 $09c26a9f-2d05-4a65-8ac1-a01ebdd7d012
		$a_81_2 = {74 65 6d 70 75 72 69 2e 6f 72 67 2f 44 61 74 61 53 65 74 41 41 41 41 41 41 41 41 41 2e 78 73 64 } //1 tempuri.org/DataSetAAAAAAAAA.xsd
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*2+(#a_81_2  & 1)*1) >=5
 
}