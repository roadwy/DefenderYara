
rule Trojan_BAT_Stealer_YCAA_MTB{
	meta:
		description = "Trojan:BAT/Stealer.YCAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 25 17 6f ?? 00 00 0a 25 18 6f ?? 00 00 0a 25 06 6f ?? 00 00 0a 25 07 6f ?? 00 00 0a 0c 08 08 6f ?? 00 00 0a 08 6f ?? 00 00 0a 6f ?? 00 00 0a 02 16 02 8e 69 6f ?? 00 00 0a 2a } //3
		$a_01_1 = {45 00 59 00 31 00 68 00 50 00 44 00 72 00 4d 00 57 00 } //1 EY1hPDrMW
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}