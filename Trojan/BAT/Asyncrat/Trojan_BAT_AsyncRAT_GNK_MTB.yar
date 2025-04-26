
rule Trojan_BAT_AsyncRAT_GNK_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.GNK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 32 1d 11 0c 5f 91 13 19 11 19 19 62 11 19 1b 63 60 d2 13 19 11 06 11 0c 11 06 11 0c 91 11 19 61 d2 9c 11 0c 17 58 13 0c 11 0c 11 07 32 d1 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}