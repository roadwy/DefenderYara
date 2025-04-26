
rule Trojan_BAT_Injuke_SCCF_MTB{
	meta:
		description = "Trojan:BAT/Injuke.SCCF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {07 03 04 6f ?? 00 00 0a 0c 02 73 ?? 00 00 0a 0d 09 08 16 73 ?? 00 00 0a 13 04 11 04 06 16 06 8e 69 6f ?? 00 00 0a 26 de 2a 11 04 } //3
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //2 CreateDecryptor
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}