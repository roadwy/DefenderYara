
rule Trojan_BAT_Rozena_AC_MTB{
	meta:
		description = "Trojan:BAT/Rozena.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0b 07 8e 69 0c 07 8e 69 8d 90 01 03 01 0d 16 13 07 2b 17 09 11 07 07 11 07 91 18 59 20 ff 00 00 00 5f d2 9c 11 07 17 58 13 07 11 07 07 8e 69 32 e2 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}