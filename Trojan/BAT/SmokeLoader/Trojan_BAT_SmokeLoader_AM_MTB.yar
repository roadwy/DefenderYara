
rule Trojan_BAT_SmokeLoader_AM_MTB{
	meta:
		description = "Trojan:BAT/SmokeLoader.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {2b 44 2b 45 2b 4a 2b 4b 18 5b 1e 2c 24 8d 2a 00 00 01 2b 42 16 2b 42 2b 1e 2b 41 2b 42 18 5b 2b 41 08 18 6f } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}