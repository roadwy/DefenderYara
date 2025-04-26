
rule Trojan_BAT_Injuke_SCXF_MTB{
	meta:
		description = "Trojan:BAT/Injuke.SCXF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 03 04 6f ?? 00 00 0a 0b 02 73 ?? 00 00 0a 0c 08 07 16 73 ?? 00 00 0a 0d 02 8e 69 8d 1c 00 00 01 13 04 09 11 04 16 11 04 8e 69 6f ?? 00 00 0a 13 05 11 04 11 05 28 ?? 00 00 2b 28 ?? 00 00 2b 13 06 de 28 } //2
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}