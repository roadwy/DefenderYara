
rule Trojan_BAT_Tedy_PSSD_MTB{
	meta:
		description = "Trojan:BAT/Tedy.PSSD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 06 6f 1a 00 00 0a 07 16 07 8e 69 6f 1b 00 00 0a 0c 08 28 33 00 00 0a 72 99 00 00 70 6f 22 00 00 0a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}