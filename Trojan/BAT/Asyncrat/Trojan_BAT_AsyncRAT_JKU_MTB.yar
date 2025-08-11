
rule Trojan_BAT_AsyncRAT_JKU_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.JKU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {28 09 00 00 0a 02 6f 0a 00 00 0a 0b 06 07 16 07 8e 69 6f 0b 00 00 0a 06 6f 0c 00 00 0a 28 0d 00 00 0a 0c dd 19 00 00 00 06 39 06 00 00 00 06 6f 0e 00 00 0a dc } //2
		$a_01_1 = {72 37 00 00 70 28 11 00 00 0a 0a 72 69 00 00 70 28 11 00 00 0a 0b 73 12 00 00 0a 0c 08 06 6f 13 00 00 0a 08 07 6f 14 00 00 0a 08 6f 15 00 00 0a 02 16 02 8e 69 6f 16 00 00 0a 0d dd 0d 00 00 00 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}