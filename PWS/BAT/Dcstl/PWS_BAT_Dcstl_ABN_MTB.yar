
rule PWS_BAT_Dcstl_ABN_MTB{
	meta:
		description = "PWS:BAT/Dcstl.ABN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 "
		
	strings :
		$a_03_0 = {0a 0a 06 72 6b 90 01 02 70 17 6f 90 01 03 0a 0b 72 90 01 03 70 0c 00 07 0d 16 13 04 2b 7c 90 0a 31 00 02 7b 90 01 03 04 72 90 01 03 70 28 90 01 03 0a 73 18 90 00 } //4
		$a_01_1 = {47 65 74 46 6f 6c 64 65 72 50 61 74 68 } //1 GetFolderPath
		$a_01_2 = {64 57 65 62 48 6f 6f 6b } //1 dWebHook
		$a_01_3 = {55 70 6c 6f 61 64 56 61 6c 75 65 73 } //1 UploadValues
		$a_01_4 = {64 69 73 63 6f 72 64 56 61 6c 75 65 73 } //1 discordValues
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=8
 
}