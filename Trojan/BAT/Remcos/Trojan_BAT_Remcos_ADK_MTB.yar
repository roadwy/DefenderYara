
rule Trojan_BAT_Remcos_ADK_MTB{
	meta:
		description = "Trojan:BAT/Remcos.ADK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 13 06 2b 41 17 13 07 16 13 08 2b 1d 07 11 06 11 08 58 91 06 11 08 6f ?? 00 00 0a d2 2e 05 16 13 07 2b 10 11 08 17 58 } //2
		$a_01_1 = {09 13 0a 2b 11 11 05 11 0a 09 59 07 11 0a 91 9c 11 0a 17 58 13 0a 11 0a 11 04 32 e9 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}