
rule Trojan_BAT_Remcos_AH_MTB{
	meta:
		description = "Trojan:BAT/Remcos.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {0b 16 0c 2b 16 07 06 08 06 8e 69 5d 91 02 08 91 61 d2 6f ?? ?? ?? 0a 08 17 58 0c 08 02 8e 69 32 } //2
		$a_01_1 = {38 00 30 00 2e 00 36 00 36 00 2e 00 37 00 35 00 2e 00 31 00 32 00 33 00 2f 00 4a 00 69 00 63 00 6f 00 74 00 5f 00 41 00 66 00 6f 00 6b 00 67 00 79 00 61 00 79 00 2e 00 70 00 6e 00 67 00 } //2 80.66.75.123/Jicot_Afokgyay.png
		$a_01_2 = {47 65 74 42 79 74 65 73 } //1 GetBytes
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}