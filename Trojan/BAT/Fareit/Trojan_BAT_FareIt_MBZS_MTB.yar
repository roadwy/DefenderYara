
rule Trojan_BAT_FareIt_MBZS_MTB{
	meta:
		description = "Trojan:BAT/FareIt.MBZS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {69 0b 07 17 59 0b 1f 64 07 5b 26 73 90 01 01 00 00 0a 0c 08 90 00 } //1
		$a_01_1 = {6f 72 64 64 65 72 32 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 } //1 ordder2.Properties.Resources.resource
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}