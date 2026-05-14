
rule Trojan_BAT_XWorm_AHRB_MTB{
	meta:
		description = "Trojan:BAT/XWorm.AHRB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {09 14 fe 01 13 04 11 04 2c 05 ?? 13 0c 2b cc ?? 2b f9 14 0a dd ?? ?? 00 00 09 08 6f ?? ?? 00 0a 00 09 08 6f ?? ?? 00 0a 00 00 09 6f ?? ?? 00 0a 13 05 } //4
		$a_03_1 = {11 07 11 08 6f ?? 00 00 0a 00 11 08 6f ?? 00 00 0a 0a dd } //2
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1) >=7
 
}