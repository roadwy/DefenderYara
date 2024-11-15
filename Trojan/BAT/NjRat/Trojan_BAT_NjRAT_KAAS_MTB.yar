
rule Trojan_BAT_NjRAT_KAAS_MTB{
	meta:
		description = "Trojan:BAT/NjRAT.KAAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_01_0 = {48 00 45 00 51 00 39 00 6b 00 32 00 55 00 51 00 41 00 6b 00 67 00 6a 00 76 } //3
		$a_01_1 = {62 00 4e 00 37 00 34 00 59 00 7a 00 7a 00 73 00 64 00 37 00 65 00 56 00 32 } //4
		$a_01_2 = {39 00 52 00 53 00 58 00 45 00 39 00 38 00 79 00 58 00 6a 00 4c 00 52 00 4b } //5
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*4+(#a_01_2  & 1)*5) >=12
 
}