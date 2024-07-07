
rule Trojan_BAT_Cryptojoker_MBFV_MTB{
	meta:
		description = "Trojan:BAT/Cryptojoker.MBFV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {4d 00 6f 00 75 00 69 00 77 00 65 00 73 00 2e 00 49 00 79 00 69 00 69 00 6d 00 74 00 6f 00 70 00 00 17 42 00 75 00 61 00 7a 00 73 00 6a 00 77 00 73 00 78 00 68 00 70 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}