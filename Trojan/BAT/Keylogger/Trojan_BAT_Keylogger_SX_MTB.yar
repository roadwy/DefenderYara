
rule Trojan_BAT_Keylogger_SX_MTB{
	meta:
		description = "Trojan:BAT/Keylogger.SX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,28 00 28 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 07 02 07 18 5a 18 6f ?? ?? 00 0a 1f 10 28 ?? ?? 00 0a 7e ?? ?? 00 04 61 d2 9c 07 17 58 0b 07 06 8e 69 32 db } //30
		$a_01_1 = {1f 1c 91 08 1f 1d 91 1e 62 60 08 1f 1e 91 1f 10 62 60 08 1f 1f 91 1f 18 } //10
	condition:
		((#a_03_0  & 1)*30+(#a_01_1  & 1)*10) >=40
 
}