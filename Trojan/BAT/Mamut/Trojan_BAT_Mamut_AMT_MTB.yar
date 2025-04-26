
rule Trojan_BAT_Mamut_AMT_MTB{
	meta:
		description = "Trojan:BAT/Mamut.AMT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 11 04 17 73 ?? 00 00 0a 0c 28 ?? 06 00 06 0d 08 09 16 09 8e 69 6f ?? 00 00 0a 07 6f ?? 00 00 0a 13 05 de 18 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Mamut_AMT_MTB_2{
	meta:
		description = "Trojan:BAT/Mamut.AMT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 04 11 04 13 09 16 13 0a 2b 28 11 09 11 0a 9a 13 05 7e 01 00 00 04 1f 64 33 05 16 13 06 de 1d 11 05 28 ?? ?? ?? 06 26 de 03 26 de 00 11 0a 17 58 13 0a 11 0a 11 09 8e 69 32 d0 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}