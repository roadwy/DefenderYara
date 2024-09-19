
rule TrojanDownloader_BAT_Pwsx_SW_MTB{
	meta:
		description = "TrojanDownloader:BAT/Pwsx.SW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {08 6f 6b 00 00 0a 20 00 b8 00 00 2f 0d 08 12 08 28 6d 00 00 0a 6f 6a 00 00 0a 11 07 17 58 13 07 11 07 07 6f 6e 00 00 0a 32 a3 } //2
		$a_01_1 = {57 68 69 73 70 65 72 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //2 Whisper.Properties.Resources.resources
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}