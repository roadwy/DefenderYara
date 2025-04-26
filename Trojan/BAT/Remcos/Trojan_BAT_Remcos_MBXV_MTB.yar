
rule Trojan_BAT_Remcos_MBXV_MTB{
	meta:
		description = "Trojan:BAT/Remcos.MBXV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {8e 69 6a 5d d4 91 58 11 ?? 11 ?? 95 58 20 ?? 00 00 00 5f } //2
		$a_01_1 = {56 00 38 00 38 00 47 00 35 00 34 00 4b 00 45 00 38 00 49 00 35 00 38 00 48 00 54 00 30 00 35 00 38 00 42 00 48 00 51 00 45 00 41 00 } //1 V88G54KE8I58HT058BHQEA
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}