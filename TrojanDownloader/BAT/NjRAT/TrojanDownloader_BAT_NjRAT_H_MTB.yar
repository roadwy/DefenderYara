
rule TrojanDownloader_BAT_NjRAT_H_MTB{
	meta:
		description = "TrojanDownloader:BAT/NjRAT.H!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 06 00 00 "
		
	strings :
		$a_01_0 = {01 14 14 14 28 } //2
		$a_01_1 = {01 13 04 11 04 16 14 a2 } //2
		$a_01_2 = {11 04 17 14 a2 } //2
		$a_01_3 = {11 04 14 14 14 17 28 } //2
		$a_01_4 = {49 00 6e 00 76 00 6f 00 6b 00 65 00 } //2 Invoke
		$a_01_5 = {45 00 6e 00 74 00 72 00 79 00 50 00 6f 00 69 00 6e 00 74 00 } //2 EntryPoint
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2) >=12
 
}