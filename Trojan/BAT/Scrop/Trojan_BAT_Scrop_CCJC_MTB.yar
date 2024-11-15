
rule Trojan_BAT_Scrop_CCJC_MTB{
	meta:
		description = "Trojan:BAT/Scrop.CCJC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {02 28 18 00 00 0a 0a 73 19 00 00 0a 28 1a 00 00 0a 72 01 00 00 70 6f 1b 00 00 0a 28 1c 00 00 0a 0b 73 1d 00 00 0a 0c 08 07 6f 1e 00 00 0a 00 08 18 6f 1f 00 00 0a 00 08 18 6f 20 00 00 0a 00 08 6f 21 00 00 0a 0d 09 06 16 06 8e 69 6f 22 00 00 0a 13 04 08 6f 23 00 00 0a 00 28 1a 00 00 0a 11 04 6f 24 00 00 0a 13 05 2b 00 11 05 2a } //2
		$a_01_1 = {3c 41 64 64 54 6f 53 74 61 72 74 75 70 42 79 52 65 67 69 73 74 72 79 41 73 79 6e 63 3e } //1 <AddToStartupByRegistryAsync>
		$a_01_2 = {3c 41 64 64 54 6f 53 74 61 72 74 75 70 42 79 53 74 61 72 74 75 70 46 6f 6c 64 65 72 41 73 79 6e 63 3e } //1 <AddToStartupByStartupFolderAsync>
		$a_01_3 = {3c 53 65 6e 64 44 61 74 61 4c 6f 6f 70 3e } //1 <SendDataLoop>
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}