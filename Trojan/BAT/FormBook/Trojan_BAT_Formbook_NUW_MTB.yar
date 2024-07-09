
rule Trojan_BAT_Formbook_NUW_MTB{
	meta:
		description = "Trojan:BAT/Formbook.NUW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {03 04 17 58 7e ?? ?? ?? 04 5d 91 0a 03 04 28 ?? ?? ?? 06 06 59 05 58 05 5d 0b 03 04 7e ?? ?? ?? 04 5d 07 d2 9c 03 0c 2b [0-01] 08 2a } //1
		$a_03_1 = {04 5d 91 0a 06 7e ?? ?? ?? 04 03 1f 16 5d 6f ?? ?? ?? 0a 61 0b 2b 00 07 2a } //1
		$a_01_2 = {06 0b 00 08 15 58 0c 08 16 fe 04 16 fe 01 0d 09 2d } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}