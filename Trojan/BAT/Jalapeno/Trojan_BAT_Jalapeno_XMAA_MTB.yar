
rule Trojan_BAT_Jalapeno_XMAA_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.XMAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_03_0 = {11 05 2a 00 11 00 72 97 00 00 70 28 ?? 00 00 06 72 c9 00 00 70 28 ?? 00 00 06 28 ?? 00 00 06 13 09 20 01 00 00 00 7e ?? 00 00 04 7b ?? 00 00 04 3a ?? 00 00 00 26 } //3
		$a_03_1 = {11 03 11 07 16 11 07 8e 69 28 ?? 00 00 06 20 } //2
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_3 = {47 65 74 42 79 74 65 41 72 72 61 79 41 73 79 6e 63 } //1 GetByteArrayAsync
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=7
 
}