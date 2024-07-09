
rule Trojan_BAT_Tedy_PTBI_MTB{
	meta:
		description = "Trojan:BAT/Tedy.PTBI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 02 07 6f 11 00 00 0a 0c 08 28 ?? 00 00 0a 0d 09 2c 25 00 08 28 ?? 00 00 0a 2d 04 1f 61 2b 02 1f 41 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}