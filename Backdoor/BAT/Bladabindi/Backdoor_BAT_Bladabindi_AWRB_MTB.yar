
rule Backdoor_BAT_Bladabindi_AWRB_MTB{
	meta:
		description = "Backdoor:BAT/Bladabindi.AWRB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 13 04 11 04 16 09 16 1f 10 28 ?? 00 00 0a 00 11 04 16 09 1f 10 1f 10 28 ?? 00 00 0a 00 07 09 6f ?? 00 00 0a 00 07 18 6f ?? 00 00 0a 00 07 18 6f ?? 00 00 0a 00 07 6f ?? 00 00 0a 13 05 02 28 ?? 00 00 0a 13 06 28 ?? 00 00 0a 11 05 11 06 16 11 06 8e 69 6f ?? 00 00 0a 6f ?? 00 00 0a 0a 2b 00 06 2a } //5
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}