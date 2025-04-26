
rule Worm_BAT_Necast_A{
	meta:
		description = "Worm:BAT/Necast.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {47 65 74 49 6e 73 74 61 6e 63 65 00 4d 61 69 6e 00 45 00 5a 49 50 00 } //1
		$a_00_1 = {72 01 00 00 70 28 20 00 00 0a 73 21 00 00 0a 0a 06 72 05 00 00 70 6f 22 00 00 0a 74 09 00 00 1b 28 14 00 00 06 28 23 00 00 0a 6f 24 00 00 0a } //1
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}