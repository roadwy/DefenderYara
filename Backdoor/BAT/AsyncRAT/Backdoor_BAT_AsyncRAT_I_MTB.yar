
rule Backdoor_BAT_AsyncRAT_I_MTB{
	meta:
		description = "Backdoor:BAT/AsyncRAT.I!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 25 0d 2c 05 09 8e 69 2d 05 16 e0 0c 2b 09 09 16 8f 1c 00 00 01 e0 0c 08 28 16 00 00 0a 13 04 11 04 07 8e 69 6a 28 17 00 00 0a 1f 40 12 05 28 01 00 00 06 26 11 04 d0 05 00 00 02 28 18 00 00 0a 28 19 00 00 0a 74 05 00 00 02 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}