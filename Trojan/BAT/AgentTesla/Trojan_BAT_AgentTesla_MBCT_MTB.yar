
rule Trojan_BAT_AgentTesla_MBCT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBCT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 0d 00 08 09 28 ?? 00 00 0a 02 28 ?? 00 00 06 6f [0-10] 6f 46 00 00 0a 00 08 18 6f ?? 00 00 0a 00 08 6f ?? 00 00 0a 13 04 07 13 05 11 04 11 05 16 11 05 8e 69 6f 49 00 00 0a 0a de 11 } //1
		$a_01_1 = {43 6c 73 45 6e 63 72 79 70 74 44 65 63 72 79 70 74 46 69 6c 65 73 } //1 ClsEncryptDecryptFiles
		$a_01_2 = {37 61 62 33 36 64 37 62 32 36 31 33 } //1 7ab36d7b2613
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule Trojan_BAT_AgentTesla_MBCT_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.MBCT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {08 07 11 07 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 6f ?? 00 00 0a 00 11 07 18 d6 13 07 11 07 11 06 31 dd } //1
		$a_01_1 = {34 00 44 00 35 00 41 00 39 00 59 00 59 00 59 00 59 00 33 00 59 00 59 00 59 00 59 00 59 00 59 00 59 00 34 00 59 00 59 00 59 00 59 00 59 00 59 00 46 00 46 00 46 00 46 00 59 00 59 00 59 00 59 00 42 00 38 00 59 00 59 00 59 00 59 00 59 00 59 00 59 00 59 00 } //1 4D5A9YYYY3YYYYYYY4YYYYYYFFFFYYYYB8YYYYYYYY
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}