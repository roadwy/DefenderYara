
rule Trojan_BAT_AsyncRAT_AMAA_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.AMAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {06 07 16 20 00 10 00 00 28 90 01 01 00 00 06 0d 09 16 31 09 08 07 16 09 28 90 01 01 00 00 06 09 16 30 e1 90 00 } //01 00 
		$a_80_1 = {69 6e 6a 65 63 74 6f 72 2e 65 78 65 } //injector.exe  00 00 
	condition:
		any of ($a_*)
 
}