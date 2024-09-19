
rule Trojan_BAT_Remcos_RP_MTB{
	meta:
		description = "Trojan:BAT/Remcos.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 06 11 05 59 08 8e 69 59 13 07 11 07 8d ?? 00 00 01 13 08 07 11 05 08 8e 69 58 11 08 16 11 07 28 ?? 00 00 0a 00 11 08 13 15 2b 00 11 15 2a } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Remcos_RP_MTB_2{
	meta:
		description = "Trojan:BAT/Remcos.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {58 07 59 61 08 61 13 12 11 12 20 ?? ?? ?? ?? 06 59 07 61 61 13 12 7e ?? ?? ?? ?? 6f ?? ?? ?? ?? 11 12 6a 6f ?? ?? ?? ?? 7e ?? ?? ?? ?? 2c 09 } //10
		$a_01_1 = {11 1f 18 91 11 1f 19 91 1f 10 62 60 11 1f 16 91 1e 62 60 11 1f 17 91 1f 18 62 60 02 65 61 } //1
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}