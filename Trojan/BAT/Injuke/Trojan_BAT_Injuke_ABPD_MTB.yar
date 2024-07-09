
rule Trojan_BAT_Injuke_ABPD_MTB{
	meta:
		description = "Trojan:BAT/Injuke.ABPD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_03_0 = {06 0c 07 08 17 73 ?? ?? ?? 0a 0d 00 09 02 28 ?? ?? ?? 06 00 09 28 ?? ?? ?? 06 00 07 28 ?? ?? ?? 06 13 04 de 2c 09 2c 07 09 6f ?? ?? ?? 0a 00 dc 90 0a 3c 00 06 28 ?? ?? ?? 06 00 06 28 } //4
		$a_01_1 = {46 6c 75 73 68 46 69 6e 61 6c 42 6c 6f 63 6b } //1 FlushFinalBlock
		$a_01_2 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
		$a_01_3 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=7
 
}