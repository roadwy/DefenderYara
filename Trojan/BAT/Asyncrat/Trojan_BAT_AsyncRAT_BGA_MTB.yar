
rule Trojan_BAT_AsyncRAT_BGA_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.BGA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 07 91 0c 06 07 06 02 07 59 17 59 91 9c 06 02 07 59 17 59 08 9c 07 17 58 0b 07 02 18 5b 32 e0 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}