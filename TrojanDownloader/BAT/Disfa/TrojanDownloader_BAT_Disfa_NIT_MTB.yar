
rule TrojanDownloader_BAT_Disfa_NIT_MTB{
	meta:
		description = "TrojanDownloader:BAT/Disfa.NIT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {06 07 02 07 91 03 07 03 8e 69 5d 91 61 d2 9c 07 17 58 0b 07 02 8e 69 32 e7 } //2
		$a_01_1 = {57 72 69 74 65 41 6c 6c 42 79 74 65 73 } //1 WriteAllBytes
		$a_01_2 = {42 6c 61 63 6b 44 72 6f 70 70 65 72 4e 45 54 } //1 BlackDropperNET
		$a_01_3 = {48 74 74 70 43 6f 6e 74 65 6e 74 } //1 HttpContent
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}