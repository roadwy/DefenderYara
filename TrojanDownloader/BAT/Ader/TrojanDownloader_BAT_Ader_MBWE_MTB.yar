
rule TrojanDownloader_BAT_Ader_MBWE_MTB{
	meta:
		description = "TrojanDownloader:BAT/Ader.MBWE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {76 00 61 00 6c 00 6f 00 72 00 61 00 6e 00 74 00 73 00 6b 00 69 00 6e 00 73 00 63 00 68 00 61 00 6e 00 67 00 65 00 72 00 2e 00 63 00 6f 00 6d 00 2f 00 6e 00 79 00 74 00 72 00 61 00 6a 00 61 00 63 00 6b 00 } //2 valorantskinschanger.com/nytrajack
		$a_01_1 = {34 65 30 32 33 66 34 33 65 31 38 39 } //1 4e023f43e189
		$a_01_2 = {49 6e 73 74 61 6c 6c 65 72 5f 73 68 61 72 70 } //1 Installer_sharp
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}