
rule Trojan_Win64_Redcap_APC_MTB{
	meta:
		description = "Trojan:Win64/Redcap.APC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {70 61 72 73 65 78 78 78 78 78 2e 74 65 78 74 } //1 parsexxxxx.text
		$a_01_1 = {2c 20 68 6f 73 74 6e 61 6d 65 3a 20 25 76 2c 20 65 6c 65 76 61 74 65 64 3a 20 } //1 , hostname: %v, elevated: 
		$a_01_2 = {50 61 79 6c 6f 61 64 28 25 76 29 20 61 63 74 69 76 65 2c 20 63 6f 6e 6e 65 63 74 69 6e 67 20 74 6f } //1 Payload(%v) active, connecting to
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}