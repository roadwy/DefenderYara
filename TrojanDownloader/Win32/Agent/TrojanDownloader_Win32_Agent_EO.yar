
rule TrojanDownloader_Win32_Agent_EO{
	meta:
		description = "TrojanDownloader:Win32/Agent.EO,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {3c 01 75 20 8d 85 cc f7 ff ff 50 ff 15 90 01 04 8d 85 cc fb ff ff 6a 00 50 ff 15 90 01 04 b3 01 eb 02 90 00 } //1
		$a_02_1 = {68 74 74 70 3a 2f 2f 90 02 30 2f 6b 69 6c 6c 73 2e 74 78 74 3f 74 69 6d 65 3d 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}