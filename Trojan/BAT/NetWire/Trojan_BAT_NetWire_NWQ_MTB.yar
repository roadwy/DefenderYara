
rule Trojan_BAT_NetWire_NWQ_MTB{
	meta:
		description = "Trojan:BAT/NetWire.NWQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {02 07 02 8e 69 5d 02 07 02 8e 69 5d 91 06 07 06 8e 69 5d 91 61 } //1
		$a_81_1 = {4f 49 59 35 34 59 35 35 5a 42 45 51 34 34 47 46 34 46 35 37 4e 35 } //1 OIY54Y55ZBEQ44GF4F57N5
	condition:
		((#a_01_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}