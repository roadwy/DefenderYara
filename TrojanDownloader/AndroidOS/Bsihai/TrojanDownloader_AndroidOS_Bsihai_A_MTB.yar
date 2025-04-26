
rule TrojanDownloader_AndroidOS_Bsihai_A_MTB{
	meta:
		description = "TrojanDownloader:AndroidOS/Bsihai.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2f 64 6f 76 69 7a 2f 74 75 72 6b 69 79 65 2f 61 70 70 } //1 com/doviz/turkiye/app
		$a_00_1 = {73 65 72 76 69 73 5f 63 61 6c 69 73 69 79 6f 72 5f 6d 75 } //1 servis_calisiyor_mu
		$a_00_2 = {67 65 74 4c 61 6e 67 69 6e 67 46 69 6c 65 } //1 getLangingFile
		$a_00_3 = {70 69 79 61 73 61 6f 7a 65 74 } //1 piyasaozet
		$a_00_4 = {54 41 47 5f 4b 52 49 50 54 4f } //1 TAG_KRIPTO
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}