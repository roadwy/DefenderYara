
rule Trojan_BAT_Zilla_SX_MTB{
	meta:
		description = "Trojan:BAT/Zilla.SX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,28 00 28 00 02 00 00 "
		
	strings :
		$a_03_0 = {9a 0c 08 28 ?? 00 00 0a 07 17 33 72 ?? ?? 1f 00 00 0a 6f ?? 00 00 0a 08 6f ?? 00 00 0a 0d 09 28 ?? 00 00 0a 13 04 02 7b 01 00 00 04 11 04 } //30
		$a_03_1 = {0b 02 07 16 12 00 28 ?? 00 00 0a 02 28 ?? 00 00 0a 59 6f ?? 00 00 0a 07 16 12 00 } //10
	condition:
		((#a_03_0  & 1)*30+(#a_03_1  & 1)*10) >=40
 
}