
rule Trojan_BAT_Remcos_PKSH_MTB{
	meta:
		description = "Trojan:BAT/Remcos.PKSH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 25 17 6f ?? 00 00 0a 25 18 6f ?? 00 00 0a 03 04 6f ?? 00 00 0a 02 16 02 8e 69 6f ?? 00 00 0a 0a de 09 } //8
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //2 CreateDecryptor
	condition:
		((#a_03_0  & 1)*8+(#a_01_1  & 1)*2) >=10
 
}