
rule Trojan_BAT_Azorult_KAA_MTB{
	meta:
		description = "Trojan:BAT/Azorult.KAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 08 91 0d 09 08 59 20 ff 00 00 00 5f 0d 09 03 1e 5d 1f 1f 5f 63 09 1e 03 1e 5d 59 1f 1f 5f 62 60 20 ff 00 00 00 5f 0d 09 03 59 20 ff 00 00 00 5f 0d 09 03 61 0d 06 08 09 d2 9c 00 08 17 58 0c } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}