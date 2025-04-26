
rule Trojan_BAT_Zilla_PLIH_MTB{
	meta:
		description = "Trojan:BAT/Zilla.PLIH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 00 70 0a 72 ?? 01 00 70 0b 72 ?? 01 00 70 0c 72 ?? 01 00 70 0d 72 ?? 01 00 70 13 04 02 1b 8d ?? 00 00 01 25 16 06 a2 25 17 07 a2 25 18 08 a2 25 19 09 a2 25 1a 11 04 a2 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}