
rule Trojan_BAT_XWormrat_RR_MTB{
	meta:
		description = "Trojan:BAT/XWormrat.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {34 35 66 63 61 66 37 30 2d 62 64 37 63 2d 34 65 61 30 2d 39 31 31 62 2d 35 35 66 61 37 33 61 61 33 36 38 64 } //1 45fcaf70-bd7c-4ea0-911b-55fa73aa368d
		$a_00_1 = {42 00 44 00 32 00 2e 00 4e 00 65 00 74 00 20 00 49 00 6e 00 6a 00 65 00 63 00 74 00 6f 00 72 00 2e 00 65 00 78 00 65 00 } //1 BD2.Net Injector.exe
		$a_00_2 = {42 00 44 00 32 00 2e 00 4e 00 65 00 74 00 5f 00 49 00 6e 00 6a 00 65 00 63 00 74 00 6f 00 72 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 BD2.Net_Injector.Properties.Resources
		$a_01_3 = {42 44 32 5f 63 6f 70 79 } //1 BD2_copy
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}