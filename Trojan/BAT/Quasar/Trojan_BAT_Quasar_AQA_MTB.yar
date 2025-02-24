
rule Trojan_BAT_Quasar_AQA_MTB{
	meta:
		description = "Trojan:BAT/Quasar.AQA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {a2 0c 16 0d 2b 0f 07 09 9a 08 09 9a 28 ?? 00 00 06 09 17 58 0d 09 07 8e 69 32 eb 08 16 9a 28 } //2
		$a_01_1 = {34 00 35 00 2e 00 38 00 33 00 2e 00 32 00 34 00 34 00 2e 00 31 00 34 00 31 00 } //1 45.83.244.141
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}