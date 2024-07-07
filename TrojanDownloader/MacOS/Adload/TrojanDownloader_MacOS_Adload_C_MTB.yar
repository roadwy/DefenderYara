
rule TrojanDownloader_MacOS_Adload_C_MTB{
	meta:
		description = "TrojanDownloader:MacOS/Adload.C!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {48 89 50 08 48 89 08 66 0f ef c0 66 0f 7f 85 80 fc ff ff 48 c7 90 01 03 ff ff 00 00 00 00 48 83 85 e8 fe ff ff 18 90 01 02 4c 89 e7 90 00 } //1
		$a_01_1 = {69 6e 6a 65 63 74 6f 72 } //1 injector
		$a_00_2 = {6b 65 79 65 6e 75 6d 65 72 61 74 6f 72 } //1 keyenumerator
		$a_01_3 = {2e 63 78 78 5f 64 65 73 74 72 75 63 74 } //1 .cxx_destruct
		$a_01_4 = {5f 6d 73 67 53 65 6e 64 53 75 70 65 72 32 } //1 _msgSendSuper2
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}