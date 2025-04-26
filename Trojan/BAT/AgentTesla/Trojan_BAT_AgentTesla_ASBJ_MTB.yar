
rule Trojan_BAT_AgentTesla_ASBJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ASBJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {13 05 11 04 8e 69 17 da 13 0c 16 13 0d 2b 1c 11 05 11 0d 11 04 11 0d 9a 1f 10 28 ?? 00 00 0a 6f ?? 00 00 0a 00 11 0d 17 d6 13 0d 11 0d 11 0c 31 de } //4
		$a_01_1 = {58 00 41 00 58 00 41 00 58 00 53 00 41 00 44 00 58 00 53 00 41 00 44 00 58 00 41 00 44 00 44 00 41 00 44 00 41 00 44 00 20 00 44 00 41 00 44 00 41 00 51 00 44 00 44 00 } //1 XAXAXSADXSADXADDADAD DADAQDD
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}