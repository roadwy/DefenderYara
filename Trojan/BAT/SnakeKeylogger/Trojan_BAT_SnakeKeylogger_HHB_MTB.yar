
rule Trojan_BAT_SnakeKeylogger_HHB_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.HHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 03 04 6f ?? 00 00 0a 0b 0e 04 05 6f ?? 00 00 0a 59 0c 06 12 01 28 ?? 00 00 0a 1f 0a 5d 03 1f 0a 5a 04 58 6f ?? 00 00 0a 00 07 08 05 } //8
		$a_01_1 = {49 00 6e 00 76 00 6f 00 6b 00 65 00 } //2 Invoke
	condition:
		((#a_03_0  & 1)*8+(#a_01_1  & 1)*2) >=10
 
}