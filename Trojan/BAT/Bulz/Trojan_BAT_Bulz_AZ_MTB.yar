
rule Trojan_BAT_Bulz_AZ_MTB{
	meta:
		description = "Trojan:BAT/Bulz.AZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {0a 0a 06 04 6f 20 00 00 0a 0b 00 07 0c 16 0d 2b 1e 08 09 9a 13 04 00 02 6f 21 00 00 0a 11 04 6f 22 00 00 0a 6f 23 00 00 0a 26 00 09 17 58 0d 09 08 8e 69 32 dc } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}