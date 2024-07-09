
rule Trojan_BAT_Heracles_DAK_MTB{
	meta:
		description = "Trojan:BAT/Heracles.DAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 1a 58 16 54 2b 2a 09 08 06 1a 58 4a 08 8e 69 5d 91 07 06 1a 58 4a 91 61 d2 6f ?? 00 00 0a 06 1e 58 06 1a 58 4a 54 06 1a 58 06 1e 58 4a 17 58 54 06 1a 58 4a 07 8e 69 32 cd } //4
		$a_01_1 = {47 65 74 42 79 74 65 73 } //1 GetBytes
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}