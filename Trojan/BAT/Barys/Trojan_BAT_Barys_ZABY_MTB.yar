
rule Trojan_BAT_Barys_ZABY_MTB{
	meta:
		description = "Trojan:BAT/Barys.ZABY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 0b 07 28 ?? 00 00 06 13 05 11 05 72 49 00 00 70 1b 8d ?? 00 00 01 13 0b 11 0b 16 72 3f 01 00 70 a2 11 0b 17 72 45 01 00 70 a2 11 0b 18 72 4d 01 00 70 a2 11 0b 19 72 51 01 00 70 a2 11 0b 1a 72 57 01 00 70 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}