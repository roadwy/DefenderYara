
rule Trojan_BAT_Saint_QLF_MTB{
	meta:
		description = "Trojan:BAT/Saint.QLF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {06 08 9a 28 ?? ?? ?? 0a 0d 09 18 5d 2d 0e 07 08 09 1f 19 58 28 ?? ?? ?? 0a 9c 2b 0c 07 08 09 1f 0f 59 28 ?? ?? ?? 0a 9c 08 17 58 0c 08 06 8e 69 17 59 32 cc } //1
		$a_01_1 = {53 70 6c 69 74 } //1 Split
		$a_01_2 = {68 65 6c 6c 6f 62 6f 7a 6f } //1 hellobozo
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}