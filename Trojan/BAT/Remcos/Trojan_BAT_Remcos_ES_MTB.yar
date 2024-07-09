
rule Trojan_BAT_Remcos_ES_MTB{
	meta:
		description = "Trojan:BAT/Remcos.ES!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_02_0 = {13 04 11 04 16 09 16 1f 10 28 ?? ?? ?? 0a 00 11 04 16 09 1f 0f 1e 28 ?? ?? ?? 0a 00 06 09 6f ?? ?? ?? 0a 00 06 18 6f ?? ?? ?? 0a 00 06 6f ?? ?? ?? 0a 13 05 02 28 ?? ?? ?? 0a 13 06 28 ?? ?? ?? 0a 11 05 11 06 16 11 06 8e 69 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 0c 08 13 08 de 0c } //10
		$a_81_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_81_2 = {54 72 69 70 6c 65 44 45 53 5f 44 65 63 72 79 70 74 } //1 TripleDES_Decrypt
	condition:
		((#a_02_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=12
 
}