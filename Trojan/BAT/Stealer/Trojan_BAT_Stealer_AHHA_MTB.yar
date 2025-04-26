
rule Trojan_BAT_Stealer_AHHA_MTB{
	meta:
		description = "Trojan:BAT/Stealer.AHHA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {03 11 0f 1f 10 63 20 ff 00 00 00 5f d2 6f ?? 00 00 0a 00 03 11 0f 1e 63 20 ff 00 00 00 5f d2 6f ?? 00 00 0a 00 03 11 0f 20 ff 00 00 00 5f d2 6f ?? 00 00 0a 00 11 06 11 0f 6a 61 13 06 06 11 06 58 0a } //3
		$a_03_1 = {01 25 16 12 08 28 ?? 00 00 0a 9c 25 17 12 08 28 ?? 00 00 0a 9c 25 18 12 08 28 ?? 00 00 0a 9c 13 10 16 } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}