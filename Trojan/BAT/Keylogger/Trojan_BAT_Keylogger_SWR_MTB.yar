
rule Trojan_BAT_Keylogger_SWR_MTB{
	meta:
		description = "Trojan:BAT/Keylogger.SWR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 72 ff 02 00 70 08 72 07 03 00 70 28 5f 00 00 0a 11 05 6f 60 00 00 0a 28 7c 00 00 0a 28 7d 00 00 0a 02 7b 0c 00 00 04 72 15 03 00 70 28 73 00 00 0a 73 6a 00 00 0a 6f 25 00 00 06 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}