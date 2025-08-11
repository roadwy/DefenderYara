
rule Trojan_BAT_Quasar_AUQ_MTB{
	meta:
		description = "Trojan:BAT/Quasar.AUQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 05 08 11 04 6f ?? 00 00 0a de 0c 11 05 2c 07 11 05 6f ?? 00 00 0a dc 73 ?? 00 00 0a 25 11 04 6f ?? 00 00 0a 25 16 6f ?? 00 00 0a 25 17 6f ?? 00 00 0a 25 17 6f } //2
		$a_01_1 = {31 00 39 00 33 00 2e 00 31 00 35 00 31 00 2e 00 31 00 30 00 38 00 2e 00 33 00 34 00 } //5 193.151.108.34
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*5) >=7
 
}