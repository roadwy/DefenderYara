
rule Trojan_BAT_Rhadamanthys_APVA_MTB{
	meta:
		description = "Trojan:BAT/Rhadamanthys.APVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {1f 09 0b 04 03 07 5d 9a 28 ?? 00 00 0a 02 28 ?? ?? 00 06 28 ?? ?? 00 0a 0a 2b 00 06 2a } //3
		$a_03_1 = {02 03 66 5f 02 66 03 5f 60 8c ?? 00 00 01 0a 2b 00 06 2a } //2
		$a_03_2 = {05 0b 16 0c 2b 11 03 08 03 08 91 08 04 28 ?? ?? 00 06 9c 08 17 d6 0c 08 07 31 eb 03 0a 2b 00 06 2a } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2+(#a_03_2  & 1)*2) >=7
 
}