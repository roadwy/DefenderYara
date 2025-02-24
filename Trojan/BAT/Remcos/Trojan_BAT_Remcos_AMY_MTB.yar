
rule Trojan_BAT_Remcos_AMY_MTB{
	meta:
		description = "Trojan:BAT/Remcos.AMY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 20 00 01 00 00 14 14 14 6f ?? ?? 00 0a 26 20 00 00 00 00 7e } //3
		$a_80_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //FromBase64String  1
		$a_80_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //CreateDecryptor  1
	condition:
		((#a_03_0  & 1)*3+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=5
 
}