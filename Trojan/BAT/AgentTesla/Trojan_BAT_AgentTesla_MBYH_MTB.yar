
rule Trojan_BAT_AgentTesla_MBYH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBYH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {17 58 08 5d [0-40] 91 11 ?? 61 13 } //1
		$a_01_1 = {38 00 37 00 35 00 35 00 38 00 53 00 37 00 45 00 37 00 32 00 50 00 38 00 34 00 48 00 47 00 43 00 43 00 47 00 47 00 48 00 35 00 47 00 } //1 87558S7E72P84HGCCGGH5G
		$a_01_2 = {4c 00 6f 00 61 00 64 00 } //1 Load
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}