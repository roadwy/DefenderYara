
rule TrojanDownloader_AndroidOS_Hydra_A_MTB{
	meta:
		description = "TrojanDownloader:AndroidOS/Hydra.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {8b 44 24 1c 8b 4c 24 1c 0f b6 8c 0b 74 32 ff ff 32 8c 03 61 32 ff ff 88 4c 24 1b 0f b6 44 24 1b 8b 4c 24 1c 88 44 0c 24 ff 44 24 1c 8b 44 24 1c 83 f8 13 72 cb } //1
		$a_00_1 = {6c 69 62 68 6f 74 65 72 2e 73 6f } //1 libhoter.so
		$a_00_2 = {5f 41 41 73 73 65 74 4d 61 6e 61 67 65 72 5f 66 72 6f 6d 4a 61 76 61 } //1 _AAssetManager_fromJava
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}