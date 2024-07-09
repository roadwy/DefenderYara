
rule Trojan_BAT_SnakeKeylogger_MP_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.MP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 04 00 00 "
		
	strings :
		$a_03_0 = {0d 08 73 3e 00 00 0a 13 04 11 04 09 06 07 6f ?? ?? ?? 0a 16 73 40 00 00 0a 13 05 11 05 73 41 00 00 0a 13 06 11 06 6f ?? ?? ?? 0a 2a 11 07 2a } //5
		$a_01_1 = {47 00 6f 00 74 00 69 00 63 00 32 00 2e 00 47 00 6f 00 74 00 69 00 63 00 32 00 } //2 Gotic2.Gotic2
		$a_01_2 = {54 00 54 00 52 00 44 00 5a 00 42 00 57 00 49 00 69 00 6d 00 6a 00 4a 00 5a 00 72 00 47 00 } //2 TTRDZBWIimjJZrG
		$a_01_3 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1) >=10
 
}