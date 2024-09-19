
rule Backdoor_BAT_AsyncRAT_PAEU_MTB{
	meta:
		description = "Backdoor:BAT/AsyncRAT.PAEU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {8e 69 5d 1f 09 58 1f ?? 58 1f ?? 59 91 61 ?? 08 20 0e 02 00 00 58 20 0d 02 00 00 } //2
		$a_03_1 = {8e 69 5d 1f 09 58 1f 0d 58 1f 16 59 91 59 20 fc 00 00 00 58 1a 58 20 00 01 00 00 5d d2 9c 08 17 58 0c 08 6a ?? 8e 69 17 59 6a 06 17 58 6e 5a 31 8f } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}