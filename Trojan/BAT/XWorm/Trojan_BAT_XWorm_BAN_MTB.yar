
rule Trojan_BAT_XWorm_BAN_MTB{
	meta:
		description = "Trojan:BAT/XWorm.BAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {07 11 04 07 11 04 91 09 11 04 09 8e 69 5d 91 61 d2 9c 11 04 17 58 13 04 11 04 07 8e 69 32 e1 07 73 15 00 00 0a 13 06 11 06 16 73 16 00 00 0a 13 07 73 0e 00 00 0a 13 08 11 07 11 08 } //2
		$a_81_1 = {49 6e 76 6f 6b 65 } //1 Invoke
	condition:
		((#a_01_0  & 1)*2+(#a_81_1  & 1)*1) >=3
 
}
rule Trojan_BAT_XWorm_BAN_MTB_2{
	meta:
		description = "Trojan:BAT/XWorm.BAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 05 11 04 ?? ?? 00 00 0a 17 73 4d 00 00 0a 13 06 11 06 09 16 09 8e 69 ?? ?? 00 00 0a 11 06 ?? ?? 00 00 0a de 10 11 07 2c 0b 11 06 2c 07 11 06 ?? ?? 00 00 0a dc 11 05 ?? ?? 00 00 0a 13 08 de 41 11 07 2c 0b 11 05 2c 07 11 05 ?? ?? 00 00 0a dc } //5
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}