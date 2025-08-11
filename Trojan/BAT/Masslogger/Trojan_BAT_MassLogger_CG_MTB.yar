
rule Trojan_BAT_MassLogger_CG_MTB{
	meta:
		description = "Trojan:BAT/MassLogger.CG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {59 13 1d 73 ?? 00 00 0a 13 1e 11 1e 72 ?? ?? 00 70 12 1b 28 ?? 00 00 0a 12 1b 28 ?? 00 00 0a 58 12 1b 28 ?? 00 00 0a 58 6c } //3
		$a_03_1 = {58 12 1b 28 ?? 00 00 0a 58 1f 0a 5a 58 } //1
		$a_01_2 = {11 1d 19 fe 04 16 fe 01 13 2a 11 2a 2c 5a } //1
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}