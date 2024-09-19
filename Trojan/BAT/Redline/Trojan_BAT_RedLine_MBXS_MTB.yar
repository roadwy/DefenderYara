
rule Trojan_BAT_RedLine_MBXS_MTB{
	meta:
		description = "Trojan:BAT/RedLine.MBXS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {45 4e 58 63 50 75 4a 7a 00 e5 a5 bd e6 8f 90 e7 94 a8 e7 ad 94 e6 9d a5 } //3
		$a_01_1 = {42 69 67 57 65 72 6b 73 2e 44 72 69 70 55 6e 69 71 75 65 } //2 BigWerks.DripUnique
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}