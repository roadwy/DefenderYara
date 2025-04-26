
rule Trojan_BAT_Quasar_MG_MTB{
	meta:
		description = "Trojan:BAT/Quasar.MG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 08 8f 26 00 00 01 25 47 07 08 07 8e 69 5d 91 61 d2 52 08 17 58 0c 08 06 8e 69 32 e3 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}