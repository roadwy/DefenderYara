
rule Trojan_BAT_Dnoper_ABGA_MTB{
	meta:
		description = "Trojan:BAT/Dnoper.ABGA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_03_0 = {73 03 00 00 0a 0a 06 20 ?? ?? 00 00 28 ?? 03 00 06 28 ?? 00 00 0a 6f ?? 00 00 0a 06 20 ?? ?? 00 00 28 ?? 03 00 06 28 ?? 00 00 0a 6f ?? 00 00 0a 06 6f ?? 00 00 0a 0b 14 0c 2b 1b } //3
		$a_03_1 = {07 08 16 08 8e 69 6f ?? 00 00 0a 0d de 0a } //2
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_3 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=7
 
}