
rule Trojan_BAT_Heracles_GPJ_MTB{
	meta:
		description = "Trojan:BAT/Heracles.GPJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_80_0 = {37 38 2e 31 31 31 2e 36 37 2e 31 38 39 } //78.111.67.189  5
		$a_80_1 = {47 65 74 42 79 74 65 41 72 72 61 79 41 73 79 6e 63 00 } //GetByteArrayAsync  2
	condition:
		((#a_80_0  & 1)*5+(#a_80_1  & 1)*2) >=7
 
}