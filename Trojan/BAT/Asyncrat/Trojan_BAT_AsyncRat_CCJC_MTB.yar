
rule Trojan_BAT_AsyncRat_CCJC_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.CCJC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {07 11 09 11 0b 58 91 08 11 0b 91 2e 05 16 13 0a 2b 0c 11 0b 17 58 13 0b 11 0b 11 05 32 e2 } //1
		$a_01_1 = {11 08 11 0c 07 11 06 11 0c 58 91 9c 11 0c 17 58 13 0c 11 0c 11 07 32 e8 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}