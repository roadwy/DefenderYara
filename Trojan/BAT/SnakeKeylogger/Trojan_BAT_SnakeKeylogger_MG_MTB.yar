
rule Trojan_BAT_SnakeKeylogger_MG_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.MG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 03 00 00 "
		
	strings :
		$a_03_0 = {13 08 12 08 28 ?? ?? ?? 0a 26 11 06 72 8d a4 10 70 72 9f a4 10 70 28 ?? ?? ?? 06 13 09 11 09 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 72 b1 a4 10 70 6f 0e 00 00 0a 72 cd a4 10 70 20 00 01 00 00 14 14 11 05 } //5
		$a_01_1 = {4e 46 53 4c 6f 63 61 6c 65 5f 4d 61 69 6e 46 6f 72 6d } //2 NFSLocale_MainForm
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=8
 
}