
rule Trojan_BAT_Quasar_PSTK_MTB{
	meta:
		description = "Trojan:BAT/Quasar.PSTK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {a2 25 1a 28 09 00 00 0a 08 6f 0a 00 00 0a a2 28 0b 00 00 0a 07 28 0c 00 00 0a 20 e0 0d 00 00 28 03 00 00 0a 1f 2e 8d 03 00 00 01 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}