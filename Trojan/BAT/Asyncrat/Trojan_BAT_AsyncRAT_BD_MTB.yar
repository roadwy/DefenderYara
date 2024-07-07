
rule Trojan_BAT_AsyncRAT_BD_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.BD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 1f 3c 28 90 01 01 00 00 06 13 05 03 11 05 1f 32 58 18 58 28 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}