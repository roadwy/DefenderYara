
rule Trojan_BAT_Scarsi_ABIO_MTB{
	meta:
		description = "Trojan:BAT/Scarsi.ABIO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {16 0a 2b 6a 00 28 ?? ?? ?? 06 73 ?? ?? ?? 0a 0b 73 ?? ?? ?? 0a 0c 07 16 73 ?? ?? ?? 0a 73 ?? ?? ?? 0a 0d 09 08 6f ?? ?? ?? 0a de 0a 09 2c 06 09 6f ?? ?? ?? 0a dc 08 6f ?? ?? ?? 0a 13 04 de 34 } //2
		$a_01_1 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
		$a_01_2 = {47 65 74 54 79 70 65 73 } //1 GetTypes
		$a_01_3 = {41 00 6a 00 74 00 62 00 74 00 62 00 63 00 74 00 63 00 } //1 Ajtbtbctc
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}