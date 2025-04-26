
rule Trojan_BAT_Quasar_MAAI_MTB{
	meta:
		description = "Trojan:BAT/Quasar.MAAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 0c 11 1c 58 11 20 11 20 8e 69 12 00 28 ?? 00 00 06 16 fe 01 13 21 11 21 2c 06 } //1
		$a_01_1 = {62 32 31 32 2d 61 34 31 33 38 30 65 37 33 37 38 35 } //1 b212-a41380e73785
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}