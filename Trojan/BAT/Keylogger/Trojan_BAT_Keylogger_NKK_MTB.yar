
rule Trojan_BAT_Keylogger_NKK_MTB{
	meta:
		description = "Trojan:BAT/Keylogger.NKK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {72 fb 01 00 70 28 ?? 00 00 0a 74 ?? 00 00 01 0b 07 6f ?? 00 00 0a 74 ?? 00 00 01 0c 08 6f ?? 00 00 0a 0d 09 73 ?? 00 00 0a 13 04 00 00 11 04 6f ?? 00 00 0a } //5
		$a_01_1 = {43 61 74 48 61 63 6b 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 CatHack.Properties.Resources
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}