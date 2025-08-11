
rule Trojan_BAT_AsyncRAT_GVA_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.GVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 66 06 20 a2 e7 ff ff 58 3b 1c 00 00 00 00 20 56 06 00 00 06 06 19 5a 06 1b 5a 58 5f 61 16 3b } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}