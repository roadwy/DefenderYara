
rule Trojan_BAT_UnixStealer_AMTB{
	meta:
		description = "Trojan:BAT/UnixStealer!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {55 6e 69 78 20 53 74 65 61 6c 65 72 } //Unix Stealer  1
		$a_80_1 = {5c 21 20 55 6e 69 78 53 74 65 61 6c 65 72 5c 42 75 69 6c 64 65 72 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 6e 65 74 36 2e 30 2d 77 69 6e 64 6f 77 73 5c 42 75 69 6c 64 65 72 2e 70 64 62 } //\! UnixStealer\Builder\obj\Release\net6.0-windows\Builder.pdb  1
		$a_80_2 = {43 72 65 61 74 65 20 79 6f 75 72 20 63 6f 6e 66 69 67 75 72 65 64 20 73 74 65 61 6c 65 72 20 65 78 65 63 75 74 61 62 6c 65 } //Create your configured stealer executable  1
		$a_80_3 = {53 61 76 65 20 53 74 65 61 6c 65 72 20 41 73 } //Save Stealer As  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}