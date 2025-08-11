
rule Trojan_BAT_Keylogger_PGK_MTB{
	meta:
		description = "Trojan:BAT/Keylogger.PGK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 06 17 6f ?? 00 00 0a 0d 09 14 fe 01 13 04 11 04 2c 0e 00 7e ?? 00 00 0a 06 6f ?? 00 00 0a 0d 00 09 07 08 6f } //2
		$a_01_1 = {6d 00 6f 00 6e 00 69 00 74 00 6f 00 72 00 69 00 6e 00 67 } //3
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*3) >=5
 
}