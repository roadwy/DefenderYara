
rule Trojan_BAT_Ader_SPS_MTB{
	meta:
		description = "Trojan:BAT/Ader.SPS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 09 11 04 09 8e 69 5d 91 08 11 04 91 61 d2 6f ?? ?? ?? 0a 11 04 17 58 13 04 11 04 08 8e 69 32 df } //4
		$a_01_1 = {38 00 30 00 2e 00 36 00 36 00 2e 00 37 00 35 00 2e 00 31 00 33 00 35 00 } //1 80.66.75.135
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}