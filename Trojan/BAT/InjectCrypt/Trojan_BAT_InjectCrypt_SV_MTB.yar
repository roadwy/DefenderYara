
rule Trojan_BAT_InjectCrypt_SV_MTB{
	meta:
		description = "Trojan:BAT/InjectCrypt.SV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 02 4a 06 6f ?? 00 00 0a 18 5b 33 ?? 02 [0-05] 54 06 28 ?? 00 00 0a 0b 07 6f ?? 00 00 0a 02 4a 91 0c 02 25 4a 17 58 54 08 2a } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}