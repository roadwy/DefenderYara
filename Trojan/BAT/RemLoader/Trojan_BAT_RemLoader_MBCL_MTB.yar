
rule Trojan_BAT_RemLoader_MBCL_MTB{
	meta:
		description = "Trojan:BAT/RemLoader.MBCL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {77 00 69 00 72 00 65 00 00 09 79 00 65 00 6e 00 6b 00 00 0b 7a 00 65 00 74 00 74 00 61 } //1
		$a_01_1 = {24 38 37 66 64 64 38 34 30 2d 65 35 37 31 2d 34 61 39 38 2d 62 39 32 31 2d 62 34 63 63 33 36 66 64 32 38 30 35 } //1 $87fdd840-e571-4a98-b921-b4cc36fd2805
		$a_01_2 = {61 44 61 79 41 74 54 68 65 52 61 63 65 73 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 } //1 aDayAtTheRaces.Properties.Resources.resource
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}