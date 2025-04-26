
rule Trojan_BAT_Ranos_A{
	meta:
		description = "Trojan:BAT/Ranos.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {53 65 72 76 53 74 61 72 74 } //ServStart  1
		$a_80_1 = {68 65 78 32 42 79 74 00 } //hex2Byt  1
		$a_80_2 = {4e 6f 77 20 45 78 65 63 75 74 69 6e 67 20 43 75 73 74 6f 6d 20 41 70 70 6c 69 63 61 74 69 6f 6e 2e 2e 2e } //Now Executing Custom Application...  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}