
rule Trojan_BAT_Remcos_ASR_MTB{
	meta:
		description = "Trojan:BAT/Remcos.ASR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 03 00 00 01 0d 16 13 04 2b 1c 09 11 04 18 5b 07 11 04 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 9c 11 04 18 58 13 04 11 04 08 32 df } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Remcos_ASR_MTB_2{
	meta:
		description = "Trojan:BAT/Remcos.ASR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {13 0e 1f 1c 28 3f 00 00 06 13 10 2b c3 11 07 11 0e 28 3d 00 00 06 16 13 10 2b b5 2b 21 11 05 17 33 0f 06 6f 6d 00 00 0a 11 07 28 3d 00 00 06 2b 0d 06 6f 6d 00 00 0a 11 07 28 20 00 00 06 11 07 16 6a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}