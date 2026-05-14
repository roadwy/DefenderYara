
rule Trojan_BAT_Barys_AQQB_MTB{
	meta:
		description = "Trojan:BAT/Barys.AQQB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {14 13 04 73 ?? 00 00 0a 0c 73 ?? 00 00 0a 0a 06 20 00 01 00 00 6f ?? 00 00 0a 06 20 80 00 00 00 6f ?? 00 00 0a 03 7e ?? 00 00 04 20 e8 03 00 00 73 ?? 00 00 0a 13 05 06 11 05 06 6f ?? 00 00 0a 1e 5b 6f ?? 00 00 0a 6f ?? 00 00 0a 06 11 05 06 6f ?? 00 00 0a 1e 5b 6f ?? 00 00 0a 6f ?? 00 00 0a 06 17 6f ?? 00 00 0a 08 06 6f ?? 00 00 0a 17 73 ?? 00 00 0a 0d 09 02 16 02 8e 69 6f ?? 00 00 0a 09 6f ?? 00 00 0a de 0f 09 14 fe 01 0b 07 2d 06 09 6f ?? 00 00 0a dc 08 6f ?? 00 00 0a 13 04 de 0f } //5
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}