
rule Trojan_BAT_AgentTesla_ASBE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ASBE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {13 04 09 8e 69 17 da 13 11 16 13 12 2b 1b 11 04 11 12 09 11 12 9a 1f 10 28 ?? 00 00 0a 6f ?? 00 00 0a 00 11 12 17 d6 13 12 11 12 11 11 31 df } //4
		$a_01_1 = {51 00 75 00 61 00 6e 00 4c 00 79 00 42 00 61 00 6e 00 47 00 69 00 61 00 79 00 2e 00 43 00 43 00 4d 00 } //1 QuanLyBanGiay.CCM
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}