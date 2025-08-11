
rule Trojan_BAT_Jalapeno_BO_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.BO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {fe 0c 14 00 fe 0c 11 00 3b 30 00 00 00 fe 0c 0b 00 fe 0c 14 00 46 fe 0c 03 00 61 52 fe 0c 14 00 20 01 00 00 00 58 fe 0e 14 00 fe 0c 0b 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}