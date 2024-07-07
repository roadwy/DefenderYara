
rule Trojan_BAT_Quasar_XZ_MTB{
	meta:
		description = "Trojan:BAT/Quasar.XZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 05 11 0a 74 40 00 00 1b 11 0c 11 07 58 11 09 59 93 61 11 0b 74 40 00 00 1b 11 09 11 0c 58 1f 11 58 11 08 5d 93 61 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}