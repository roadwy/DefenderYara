
rule TrojanDownloader_BAT_Pwsx_SV_MTB{
	meta:
		description = "TrojanDownloader:BAT/Pwsx.SV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {07 11 05 08 5d 08 58 08 5d 91 11 06 61 11 08 59 20 00 02 00 00 58 13 09 16 13 12 } //2
		$a_01_1 = {52 65 6d 6f 74 65 57 67 65 74 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 RemoteWget.Properties.Resources
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}