
rule Trojan_BAT_Rhadamanthys_APOB_MTB{
	meta:
		description = "Trojan:BAT/Rhadamanthys.APOB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 0d 11 11 6f ?? 00 00 0a 17 73 ?? 00 00 0a 13 02 38 00 00 00 00 00 11 02 02 16 02 8e 69 6f ?? 00 00 0a 38 5b 00 00 00 38 09 00 00 00 20 00 00 00 00 fe 0e 0e 00 fe 0c 0e 00 45 01 00 00 00 4c 00 00 00 fe 0c 0e 00 20 dc 03 00 00 3b ?? ff ff ff 38 39 00 00 00 11 0d 6f ?? 00 00 0a 73 ?? 00 00 0a 13 0c 20 00 00 00 00 7e ?? 00 00 04 7b ?? 00 00 04 3a ?? ff ff ff 26 20 05 00 00 00 38 ?? ff ff ff 11 02 6f ?? 00 00 0a 38 } //5
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}