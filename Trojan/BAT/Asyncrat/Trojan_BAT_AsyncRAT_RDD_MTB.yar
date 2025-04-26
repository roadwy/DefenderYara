
rule Trojan_BAT_AsyncRAT_RDD_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.RDD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {02 28 13 00 00 0a 28 27 00 00 0a 0a 06 28 ?? ?? ?? ?? 6f 1a 00 00 0a 0b 07 2c ?? 02 20 00 01 00 00 8d 0d 00 00 01 7d ?? ?? ?? ?? 07 02 7b ?? ?? ?? ?? 16 02 7b ?? ?? ?? ?? 8e 69 6f 2c 00 00 0a 26 } //2
		$a_03_1 = {08 06 08 06 93 02 7b ?? ?? ?? ?? 07 91 04 60 61 d1 9d 06 17 59 25 0a 16 2f } //2
		$a_01_2 = {35 32 39 62 62 64 63 36 32 37 35 65 61 36 65 63 } //1 529bbdc6275ea6ec
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}