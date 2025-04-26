
rule Trojan_BAT_Injector_EAPQ_MTB{
	meta:
		description = "Trojan:BAT/Injector.EAPQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {03 11 0c 16 11 0a 6f 44 00 00 0a 26 11 09 11 0c 16 11 0a 11 0b 16 6f 4f 00 00 0a 13 0e 7e 0a 00 00 04 11 0b 16 11 0e 6f 50 00 00 0a 11 0d 11 0a 58 13 0d 11 0d 11 0a 58 6a 03 6f 48 00 00 0a 32 bf } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}