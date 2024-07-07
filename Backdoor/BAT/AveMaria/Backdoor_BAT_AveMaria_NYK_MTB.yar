
rule Backdoor_BAT_AveMaria_NYK_MTB{
	meta:
		description = "Backdoor:BAT/AveMaria.NYK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {43 00 4d 00 43 00 65 00 43 00 74 00 43 00 68 00 43 00 6f 00 43 00 64 00 43 00 30 00 43 00 43 00 43 00 43 00 43 00 43 00 43 00 43 00 43 00 } //1 CMCeCtChCoCdC0CCCCCCCCC
		$a_01_1 = {53 00 64 00 56 00 62 00 63 00 73 00 6b 00 6c 00 64 00 66 00 6a 00 70 00 } //1 SdVbcskldfjp
		$a_01_2 = {47 00 65 00 74 00 4d 00 61 00 6e 00 69 00 66 00 65 00 73 00 74 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 53 00 74 00 72 00 65 00 61 00 6d 00 } //1 GetManifestResourceStream
		$a_01_3 = {70 00 6a 00 64 00 66 00 73 00 67 00 79 00 75 00 66 00 69 00 75 00 6a 00 67 00 } //1 pjdfsgyufiujg
		$a_01_4 = {78 00 63 00 6b 00 6a 00 76 00 62 00 76 00 69 00 67 00 66 00 6f 00 72 00 67 00 } //1 xckjvbvigforg
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}