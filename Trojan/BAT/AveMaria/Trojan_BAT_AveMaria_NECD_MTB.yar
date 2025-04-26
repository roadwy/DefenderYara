
rule Trojan_BAT_AveMaria_NECD_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NECD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 04 00 00 "
		
	strings :
		$a_01_0 = {61 00 2e 00 70 00 6f 00 6d 00 66 00 2e 00 63 00 61 00 74 00 } //10 a.pomf.cat
		$a_01_1 = {31 39 2e 31 30 2e 32 30 30 36 39 2e 34 39 38 32 36 } //5 19.10.20069.49826
		$a_01_2 = {50 6f 77 65 72 65 64 20 62 79 20 53 6d 61 72 74 41 73 73 65 6d 62 6c 79 20 38 2e 31 2e 30 2e 34 38 39 32 } //2 Powered by SmartAssembly 8.1.0.4892
		$a_01_3 = {41 64 6f 62 65 20 41 63 72 6f 62 61 74 20 44 43 } //1 Adobe Acrobat DC
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*5+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1) >=18
 
}