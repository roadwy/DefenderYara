
rule Trojan_BAT_Remcos_EWB_MTB{
	meta:
		description = "Trojan:BAT/Remcos.EWB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_03_0 = {06 07 16 20 00 10 00 00 6f ?? ?? ?? 0a 0d 09 16 fe 02 13 04 11 04 2c 0c 00 08 07 16 09 6f ?? ?? ?? 0a 00 00 00 09 16 fe 02 13 05 11 05 2d d0 } //1
		$a_01_1 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
		$a_01_2 = {47 65 74 54 79 70 65 } //1 GetType
		$a_01_3 = {54 00 6f 00 6d 00 61 00 73 00 7a 00 5a 00 61 00 77 00 61 00 64 00 7a 00 6b 00 69 00 5f 00 5a 00 61 00 64 00 44 00 6f 00 6d 00 32 00 } //1 TomaszZawadzki_ZadDom2
		$a_01_4 = {41 00 6d 00 6d 00 69 00 74 00 2e 00 50 00 65 00 61 00 72 00 6c 00 } //1 Ammit.Pearl
		$a_01_5 = {42 00 75 00 74 00 61 00 } //1 Buta
		$a_01_6 = {49 00 6e 00 76 00 6f 00 6b 00 65 00 } //1 Invoke
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}