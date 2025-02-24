
rule Trojan_BAT_Stealer_PAFU_MTB{
	meta:
		description = "Trojan:BAT/Stealer.PAFU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_03_0 = {0b 16 0c 38 ?? ?? ?? ?? 06 07 08 18 6f ?? ?? ?? ?? 1f 10 28 ?? ?? ?? ?? 6f ?? ?? ?? ?? 08 18 58 0c 08 07 6f ?? ?? ?? ?? 32 de 06 2a } //2
		$a_03_1 = {0a 02 06 28 ?? ?? ?? ?? 0b 14 0c 07 39 11 00 00 00 } //2
		$a_03_2 = {20 e8 03 00 00 28 ?? ?? ?? ?? 06 17 58 0a 06 1b 32 ee } //2
		$a_01_3 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_03_2  & 1)*2+(#a_01_3  & 1)*1) >=7
 
}