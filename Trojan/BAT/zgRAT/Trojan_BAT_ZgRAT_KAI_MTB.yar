
rule Trojan_BAT_ZgRAT_KAI_MTB{
	meta:
		description = "Trojan:BAT/ZgRAT.KAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 07 03 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 0c 08 59 20 00 00 01 00 58 20 00 00 01 00 5d 0d 06 09 d1 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}