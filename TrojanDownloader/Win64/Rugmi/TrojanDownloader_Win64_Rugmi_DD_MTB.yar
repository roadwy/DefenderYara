
rule TrojanDownloader_Win64_Rugmi_DD_MTB{
	meta:
		description = "TrojanDownloader:Win64/Rugmi.DD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 83 10 01 00 00 83 f8 14 0f 85 fa 00 00 00 48 8b 8b 20 01 00 00 48 8d 54 24 40 8d 70 ed e8 f1 00 ff ff 81 bf 94 01 00 00 00 01 00 00 74 08 81 3f 00 01 00 00 } //1
		$a_01_1 = {66 89 45 f2 8b 45 fc 69 d0 3f 00 01 00 0f b7 45 f2 01 d0 89 45 fc 83 45 f8 01 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}