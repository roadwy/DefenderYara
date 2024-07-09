
rule Trojan_BAT_Quasar_NSQ_MTB{
	meta:
		description = "Trojan:BAT/Quasar.NSQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {28 10 00 00 0a 72 ?? 00 00 70 02 73 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 06 02 6f ?? 00 00 0a 0b 25 07 28 ?? 00 00 0a 28 ?? 00 00 0a 26 } //5
		$a_01_1 = {6b 00 58 00 46 00 70 00 5a 00 42 00 62 00 } //1 kXFpZBb
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}