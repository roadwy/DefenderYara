
rule Trojan_BAT_Nanocore_AYNB_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.AYNB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_01_0 = {16 02 8e b7 17 59 0c 0b 2b 0d 02 07 02 07 91 1e 61 d2 9c 07 1e 58 0b 07 08 31 ef 02 2a } //5
		$a_03_1 = {0a 16 02 6f ?? 00 00 0a 17 59 0d 0c 2b 1e 06 02 08 6f ?? 00 00 0a 1e 59 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 0a 08 17 58 0c 08 09 31 de } //2
	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*2) >=7
 
}