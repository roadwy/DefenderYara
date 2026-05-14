
rule Trojan_BAT_XWorm_AZNB_MTB{
	meta:
		description = "Trojan:BAT/XWorm.AZNB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_01_0 = {16 02 8e b7 17 59 0c 0b 2b 0f 02 07 02 07 91 1f 0a 61 d2 9c 07 1f 0a 58 0b 07 08 31 ed 02 2a } //5
		$a_03_1 = {0b 16 02 6f ?? 00 00 0a 17 59 0d 0c 2b 1f 07 02 08 6f ?? 00 00 0a 1f 0a 59 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 0b 08 17 58 0c 08 09 31 dd 07 2a } //2
	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*2) >=7
 
}