
rule TrojanDownloader_BAT_CryptInject_BC_MTB{
	meta:
		description = "TrojanDownloader:BAT/CryptInject.BC!MTB,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {fe 09 02 00 61 d1 9d fe 0c 00 00 20 cc ac 85 bb 20 02 00 00 00 63 20 07 6e 99 06 58 66 20 02 00 00 00 62 20 1c 9b ff 1b 59 66 20 06 00 eb f1 59 59 25 fe 0e 00 00 20 19 a8 be fa 20 19 a8 be fa 59 } //1
		$a_01_1 = {65 5f 6d 61 67 69 63 } //1 e_magic
		$a_01_2 = {53 69 7a 65 4f 66 49 6d 61 67 65 } //1 SizeOfImage
		$a_01_3 = {4f 70 74 69 6f 6e 61 6c 48 65 61 64 65 72 } //1 OptionalHeader
		$a_01_4 = {65 5f 6c 66 61 6e 65 77 } //1 e_lfanew
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}