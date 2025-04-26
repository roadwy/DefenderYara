
rule Trojan_BAT_AsyncRAT_AMAA_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.AMAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 07 16 20 00 10 00 00 28 ?? 00 00 06 0d 09 16 31 09 08 07 16 09 28 ?? 00 00 06 09 16 30 e1 } //5
		$a_80_1 = {69 6e 6a 65 63 74 6f 72 2e 65 78 65 } //injector.exe  1
	condition:
		((#a_03_0  & 1)*5+(#a_80_1  & 1)*1) >=6
 
}
rule Trojan_BAT_AsyncRAT_AMAA_MTB_2{
	meta:
		description = "Trojan:BAT/AsyncRAT.AMAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 0d 07 16 08 16 1f 10 28 ?? 00 00 0a 00 07 1f 10 09 16 1f 10 28 ?? 00 00 0a 00 73 ?? 00 00 0a 08 09 6f ?? 00 00 0a 13 04 04 73 ?? 00 00 0a 13 05 73 ?? 00 00 0a 13 06 00 11 05 11 04 16 73 ?? 00 00 0a 13 07 00 11 07 11 06 6f ?? 00 00 0a 00 00 de 0d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}