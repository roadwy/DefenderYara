
rule Trojan_BAT_Lazy_RDE_MTB{
	meta:
		description = "Trojan:BAT/Lazy.RDE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 23 00 00 00 00 00 00 3a 40 07 6f 8a 00 00 0a 5a 23 00 00 00 00 00 40 50 40 58 28 8b 00 00 0a 28 8c 00 00 0a 28 8d 00 00 0a 0d 12 03 28 8e 00 00 0a 28 8f 00 00 0a 0a 08 17 58 0c 08 1b } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}