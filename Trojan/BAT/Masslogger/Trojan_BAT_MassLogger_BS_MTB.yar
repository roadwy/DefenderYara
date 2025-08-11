
rule Trojan_BAT_MassLogger_BS_MTB{
	meta:
		description = "Trojan:BAT/MassLogger.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {0a 18 5d 16 fe 01 0b 19 8d ?? 00 00 01 25 16 } //2
		$a_01_1 = {04 fe 04 2b 01 16 } //1
		$a_01_2 = {5a 20 ff 00 00 00 5d } //1
		$a_01_3 = {1b fe 02 2b 01 16 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}