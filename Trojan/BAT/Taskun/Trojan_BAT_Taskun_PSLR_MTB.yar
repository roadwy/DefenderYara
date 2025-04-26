
rule Trojan_BAT_Taskun_PSLR_MTB{
	meta:
		description = "Trojan:BAT/Taskun.PSLR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 02 72 d6 07 00 70 72 d1 01 00 70 6f 5d 00 00 0a 72 da 07 00 70 72 e0 07 00 70 6f 5d 00 00 0a 13 02 38 c2 f6 ff ff 02 7b 12 00 00 04 6f 2d 00 00 0a 02 7b 2d 00 00 04 6f 2e 00 00 0a 38 24 17 00 00 02 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}