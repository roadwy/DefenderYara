
rule Trojan_BAT_NjRat_NEDK_MTB{
	meta:
		description = "Trojan:BAT/NjRat.NEDK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 06 28 4b 00 00 0a 72 e6 25 01 70 18 18 28 29 00 00 06 0b 07 28 ?? 00 00 0a 0c 08 6f ?? 00 00 0a 14 14 6f ?? 00 00 0a 26 00 2a } //10
		$a_01_1 = {49 00 6e 00 74 00 65 00 6c 00 6c 00 69 00 4c 00 6f 00 63 00 6b 00 } //2 IntelliLock
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*2) >=12
 
}