
rule Trojan_BAT_AgentTesla_CAZ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 06 72 ed 05 00 70 28 ?? 00 00 06 6f ?? 00 00 0a 00 06 18 6f ?? 00 00 0a 00 06 18 6f ?? 00 00 0a 00 06 6f ?? 00 00 0a 0b 07 02 16 02 8e 69 6f ?? 00 00 0a 0c 2b 00 08 2a } //3
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_2 = {74 00 4c 00 79 00 56 00 5a 00 39 00 37 00 47 00 4f 00 79 00 6c 00 63 00 6a 00 71 00 55 00 6c 00 48 00 79 00 48 00 78 00 4a 00 51 00 65 00 79 00 4b 00 39 00 43 00 6e 00 43 00 32 00 52 00 32 00 4f 00 6c 00 4b 00 76 00 4b 00 77 00 77 00 78 00 5a 00 43 00 6b 00 } //1 tLyVZ97GOylcjqUlHyHxJQeyK9CnC2R2OlKvKwwxZCk
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}