
rule Trojan_BAT_Remcos_AFSQ_MTB{
	meta:
		description = "Trojan:BAT/Remcos.AFSQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {7e 02 00 00 04 6f ?? ?? ?? 0a 02 16 02 8e 69 6f ?? ?? ?? 0a 0a 2b 00 06 } //2
		$a_01_1 = {48 00 65 00 6c 00 70 00 65 00 72 00 5f 00 43 00 6c 00 61 00 73 00 73 00 65 00 73 00 } //1 Helper_Classes
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}