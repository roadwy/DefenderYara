
rule Trojan_BAT_Keylogger_PSVW_MTB{
	meta:
		description = "Trojan:BAT/Keylogger.PSVW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 16 73 0e 00 00 0a 0c 73 0f 00 00 0a 0d 08 09 28 ?? 00 00 06 09 16 6a 6f ?? 00 00 0a 09 13 04 de 1c } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}