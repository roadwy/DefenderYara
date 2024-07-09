
rule Trojan_BAT_Formbook_NVG_MTB{
	meta:
		description = "Trojan:BAT/Formbook.NVG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 13 04 2b 00 02 03 17 58 7e ?? ?? ?? 04 5d 91 0a 16 0b 16 13 05 2b 00 02 03 1f 16 28 ?? ?? ?? 06 0c 06 04 58 0d 08 09 59 04 5d 0b 16 13 06 2b 00 02 03 7e ?? ?? ?? 04 5d 07 28 } //1
		$a_01_1 = {53 00 79 00 73 00 74 00 65 00 6d 00 2e 00 52 00 65 00 66 00 6c 00 65 00 63 00 74 00 69 00 6f 00 6e 00 2e 00 41 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 } //1 System.Reflection.Assembly
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}