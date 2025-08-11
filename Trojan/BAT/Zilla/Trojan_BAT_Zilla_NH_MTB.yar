
rule Trojan_BAT_Zilla_NH_MTB{
	meta:
		description = "Trojan:BAT/Zilla.NH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {06 08 91 18 5b 1f 0f 58 0d 07 09 d1 13 04 12 04 28 ?? 00 00 0a 28 ?? 00 00 0a 0b 08 18 58 0c 08 06 8e 69 32 db } //2
		$a_03_1 = {a2 25 18 72 ?? 09 00 70 a2 25 19 08 6f ?? 00 00 06 a2 25 1a 72 ?? 09 00 70 a2 28 ?? 00 00 0a 0a 07 6f ?? 00 00 0a 2d b5 } //1
		$a_01_2 = {41 6e 6b 65 74 69 72 6f 76 61 6e 69 65 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 Anketirovanie.Properties.Resources.resources
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}