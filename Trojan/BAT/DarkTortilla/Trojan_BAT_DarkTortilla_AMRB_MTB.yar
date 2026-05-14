
rule Trojan_BAT_DarkTortilla_AMRB_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.AMRB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {11 0f 07 6f ?? ?? 00 0a 00 11 0f 07 6f ?? ?? 00 0a 00 11 0f 17 6f ?? ?? 00 0a 1b 13 3a 2b c0 00 11 0f 18 6f ?? ?? 00 0a 00 00 11 0f 6f ?? ?? 00 0a 13 10 } //4
		$a_03_1 = {04 11 08 11 10 28 ?? ?? 00 06 28 ?? 00 00 2b 6f ?? ?? 00 0a 00 de 45 } //2
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1) >=7
 
}