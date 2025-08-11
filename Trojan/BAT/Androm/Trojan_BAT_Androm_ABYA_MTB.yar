
rule Trojan_BAT_Androm_ABYA_MTB{
	meta:
		description = "Trojan:BAT/Androm.ABYA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 08 06 08 91 03 08 03 8e 69 5d 91 61 d2 9c 16 0d 2b 18 06 08 06 08 91 03 09 91 07 1f 1f 5f 62 09 61 08 58 61 d2 9c 09 17 58 0d 09 03 8e 69 32 e2 08 17 58 0c 08 06 8e 69 32 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}