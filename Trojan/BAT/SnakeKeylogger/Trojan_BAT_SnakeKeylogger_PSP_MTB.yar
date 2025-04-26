
rule Trojan_BAT_SnakeKeylogger_PSP_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.PSP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {16 11 0c 09 59 28 ?? ?? ?? 0a 13 0d 11 0c 09 58 17 58 04 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 13 0e 11 0d 13 0f 2b 42 00 07 11 0f 91 13 10 11 10 2c 02 } //1
		$a_01_1 = {5a 69 6e 64 67 65 53 61 78 74 65 } //1 ZindgeSaxte
		$a_01_2 = {45 7a 6c 65 6e 6b 6f 6b 61 } //1 Ezlenkoka
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}