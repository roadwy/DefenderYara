
rule TrojanDownloader_BAT_FormBook_AE_MTB{
	meta:
		description = "TrojanDownloader:BAT/FormBook.AE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {24 36 31 39 38 39 64 61 35 2d 30 33 36 35 2d 34 35 32 31 2d 39 31 39 36 2d 36 65 39 34 35 62 38 61 39 38 36 38 } //1 $61989da5-0365-4521-9196-6e945b8a9868
		$a_01_1 = {59 55 45 57 55 59 44 53 48 4a 44 53 36 35 33 32 35 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 YUEWUYDSHJDS65325.Properties.Resources.resources
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_3 = {47 65 74 52 65 73 70 6f 6e 73 65 53 74 72 65 61 6d } //1 GetResponseStream
		$a_01_4 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
		$a_81_5 = {52 52 55 55 4e 4e 4e } //1 RRUUNNN
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}