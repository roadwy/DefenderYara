
rule Trojan_BAT_Quasar_MBCW_MTB{
	meta:
		description = "Trojan:BAT/Quasar.MBCW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {72 01 00 00 70 0a 06 28 ?? 00 00 0a 0b 28 ?? 00 00 0a 07 16 07 8e 69 6f ?? 00 00 0a 0a 28 ?? 00 00 0a 06 6f ?? 00 00 0a 0c 21 61 00 00 00 00 00 00 00 } //1
		$a_01_1 = {51 75 61 73 61 72 20 43 6c 69 65 6e 74 00 00 0a 01 00 05 31 2e 34 2e 30 00 00 09 15 12 84 fd } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}