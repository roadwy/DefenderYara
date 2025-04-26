
rule Backdoor_BAT_CryptoDropper_MTB{
	meta:
		description = "Backdoor:BAT/CryptoDropper!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {fe 0e 00 00 00 11 00 59 7e ?? ?? ?? 04 61 d1 2a 90 0a 50 00 fe 0e 01 00 fe 0c 00 00 fe 0c 01 00 58 [0-25] 20 20 05 00 00 [0-10] fe 0e 00 00 00 38 [0-20] fe 0e 00 00 00 11 00 59 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}