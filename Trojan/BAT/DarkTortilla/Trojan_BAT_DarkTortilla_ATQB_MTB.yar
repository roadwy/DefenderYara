
rule Trojan_BAT_DarkTortilla_ATQB_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.ATQB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 1d 5f 0b 00 28 ?? ?? 00 06 0c 2b 00 2b 00 00 73 ?? ?? 00 0a 0d 2b 00 00 09 08 28 ?? ?? 00 06 13 04 2b 00 02 14 fe 03 13 05 11 04 02 28 ?? ?? 00 06 00 09 6f ?? ?? 00 0a 0a dd } //4
		$a_03_1 = {02 03 16 03 8e 69 6f ?? ?? 00 0a 00 02 6f ?? ?? 00 0a 18 0b 2b cf } //2
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1) >=7
 
}